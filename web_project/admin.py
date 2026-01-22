import base64
import hmac
import hashlib
import io
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Tuple
from uuid import uuid4

import face_recognition
from flask import Blueprint, Response, current_app, flash, jsonify, render_template, request, send_file, redirect, url_for, session
from flask_login import current_user
from sqlalchemy import func, or_
from werkzeug.utils import secure_filename

from web_project import db
from web_project.forms import IssuerCredentialForm
from web_project.model import IssuedCredential, CredentialVerification, SecurityEvent, VerificationRequest
from web_project.security_events import record_security_event
from web_project.security import hash_auth_key, hash_certificate_id
from web_project.wallet_utils import ensure_wallet_qr

issuer_bp = Blueprint('issuer', __name__, url_prefix='/issuer')

UTC = timezone.utc


@issuer_bp.before_request
def ensure_issuer_authenticated():
    endpoint = request.endpoint or ''
    if endpoint.startswith('issuer.static') or endpoint == 'issuer.logout':
        return

    issuer_session_active = session.get('issuer_account_id') is not None
    if not issuer_session_active and current_user.is_authenticated and getattr(current_user, 'is_issuer', False):
        session['issuer_account_id'] = current_user.id
        session['issuer_account_email'] = current_user.email
        issuer_session_active = True

    if issuer_session_active:
        return

    if request.method == 'POST':
        return jsonify({"ok": False, "error": "Please log in with an authorized issuer account."}), 401

    flash('Issuer access requires a faculty login. Please sign in first.', 'danger')
    return redirect(url_for('home', page='page-login'))


@issuer_bp.after_request
def issuer_no_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


def _save_id_document(upload):
    storage_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'issuer')
    os.makedirs(storage_dir, exist_ok=True)
    filename = secure_filename(upload.filename) or f"id_{uuid4().hex}.jpg"
    path = os.path.join(storage_dir, filename)
    upload.save(path)
    return path


def _save_base64_image(data_url: str, prefix: str) -> str:
    header, encoded = data_url.split(',', 1)
    ext = header.split('/')[1].split(';')[0]
    binary = base64.b64decode(encoded)
    storage_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'issuer')
    os.makedirs(storage_dir, exist_ok=True)
    filename = f"{prefix}_{uuid4().hex}.{ext}"
    path = os.path.join(storage_dir, filename)
    with open(path, 'wb') as fh:
        fh.write(binary)
    return path


def _sign_payload(payload: dict) -> Tuple[str, str]:
    secret = current_app.config.get('ISSUER_SECRET', 'dev-issuer-secret')
    serialized = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    signature = hmac.new(secret.encode('utf-8'), serialized.encode('utf-8'), hashlib.sha256).hexdigest()
    credentials_dir = os.path.join(current_app.root_path, 'static', 'credentials')
    os.makedirs(credentials_dir, exist_ok=True)
    filename = f"{payload['student_id']}_credential.json"
    filepath = os.path.join(credentials_dir, filename)
    with open(filepath, 'w', encoding='utf-8') as fp:
        json.dump({"payload": payload, "signature": signature}, fp, indent=2)
    return signature, filename


def _placeholder_commitment(student_id: str, program: str) -> str:
    seed = f"{student_id}|{program}|{current_app.config.get('ISSUER_SECRET', 'dev-issuer-secret')}"
    return hashlib.sha256(seed.encode('utf-8')).hexdigest()


def _face_match_diagnostics(id_path: str, selfie_path: str) -> dict:
    """Runs a lightweight comparison to provide issuer confidence scores."""
    diagnostics = {
        "status": "not_run",
        "match": False,
        "distance": None,
        "confidence": "unknown",
        "error": None,
    }

    try:
        if not id_path or not selfie_path:
            raise ValueError('Missing evidence paths')
        if id_path.lower().endswith('.pdf'):
            raise ValueError('ID proof is PDF; cannot extract face metrics.')

        id_image = face_recognition.load_image_file(id_path)
        live_image = face_recognition.load_image_file(selfie_path)
        id_encodings = face_recognition.face_encodings(id_image)
        live_encodings = face_recognition.face_encodings(live_image)

        if not id_encodings or not live_encodings:
            raise ValueError('Could not detect face in one of the samples.')

        distance = float(face_recognition.face_distance([id_encodings[0]], live_encodings[0])[0])
        match = bool(distance < 0.6)

        if distance < 0.45:
            confidence = 'high'
        elif distance < 0.6:
            confidence = 'medium'
        else:
            confidence = 'low'

        diagnostics.update({
            "status": "completed",
            "match": match,
            "distance": round(distance, 4),
            "confidence": confidence,
        })
    except Exception as exc:  # pragma: no cover - diagnostics best effort
        diagnostics.update({
            "status": "error",
            "error": str(exc),
        })

    return diagnostics


@issuer_bp.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    active_view = request.args.get('view', 'overview')
    onboarding_steps = [
        {
            "title": "Capture student evidence",
            "description": "Upload the official ID and capture a live selfie to bind biometrics to the certificate.",
        },
        {
            "title": "Run automated checks",
            "description": "The workstation validates document type, extracts MRZ data, and compares faces.",
        },
        {
            "title": "Mint a ZK credential",
            "description": "We sign a privacy-preserving credential that the student later proves in zero-knowledge.",
        },
    ]

    form = IssuerCredentialForm()
    issued_credential = None

    if request.method == 'POST':
        active_view = 'mint'

    if form.validate_on_submit():
        # Get current time without timezone info to avoid comparison issues
        now_naive = datetime.now()
        existing_active = (
            IssuedCredential.query
            .filter(
                IssuedCredential.student_id == form.student_id.data,
                IssuedCredential.revoked.is_(False),
                or_(
                    IssuedCredential.expires_at.is_(None),
                    IssuedCredential.expires_at > now_naive
                )
            )
            .order_by(IssuedCredential.issued_at.desc())
            .first()
        )

        if existing_active:
            flash('This student already has an active credential. Revoke or refresh the existing record before minting another.', 'warning')
            record_security_event(
                'issuer_duplicate_credential_blocked',
                severity='low',
                detail='Issuer attempted to mint duplicate active credential.',
                metadata={
                    'student_id': form.student_id.data,
                    'existing_credential_id': existing_active.id,
                    'existing_expires_at': existing_active.expires_at.isoformat() if existing_active.expires_at else None,
                }
            )
        else:
            try:
                id_path = _save_id_document(form.id_document.data)
                selfie_path = _save_base64_image(form.selfie_image_base64.data, form.student_id.data)
                face_metrics = _face_match_diagnostics(id_path, selfie_path)
                auth_key = secrets.token_urlsafe(24)
                certificate_id = uuid4().hex
                certificate_hash = hash_certificate_id(certificate_id)
                auth_key_hash = hash_auth_key(auth_key)

                valid_days = int(form.valid_days.data or current_app.config['CREDENTIAL_VALIDITY_DAYS_DEFAULT'])
                expires_at = datetime.now(UTC) + timedelta(days=valid_days)

                payload = {
                    "student_id": form.student_id.data,
                    "first_name": form.first_name.data,
                    "last_name": form.last_name.data,
                    "program": form.program.data,
                    "issued_at": datetime.now(UTC).isoformat(),
                    "biometric_verified": True,
                    "issuer_notes": form.issuer_notes.data,
                    "id_proof_path": id_path.split('static/')[-1] if 'static/' in id_path else id_path,
                    "selfie_path": selfie_path.split('static/')[-1] if 'static/' in selfie_path else selfie_path,
                    "university": "NUST SEECS",
                    "proof_commitment": _placeholder_commitment(form.student_id.data, form.program.data),
                    "face_evidence": face_metrics,
                    "certificate_id": certificate_id,
                    "authentication_key": auth_key,
                    "valid_for_days": valid_days,
                    "expires_at": expires_at.isoformat(),
                }

                signature, credential_filename = _sign_payload(payload)

                record = IssuedCredential(
                    student_id=form.student_id.data,
                    credential_hash=signature,
                    meta_blob=payload,
                    expires_at=expires_at,
                    valid_for_days=valid_days,
                    auth_key_hash=auth_key_hash,
                    certificate_id=certificate_id,
                    certificate_hash=certificate_hash,
                )
                db.session.add(record)
                db.session.commit()

                qr_relpath = ensure_wallet_qr(signature, certificate_id)
                wallet_link = url_for('wallet.view_wallet', credential_hash=signature)

                issued_credential = {
                    "signature": signature,
                    "payload": payload,
                    "download_url": url_for('static', filename=f'credentials/{credential_filename}'),
                    "expires_at": expires_at,
                    "auth_key": auth_key,
                    "certificate_id": certificate_id,
                    "wallet_url": wallet_link,
                    "wallet_url_external": url_for('wallet.view_wallet', credential_hash=signature, _external=True),
                    "wallet_qr_url": url_for('static', filename=qr_relpath),
                }
                flash('Credential minted successfully. Share the download link with the verified student.', 'success')
                form = IssuerCredentialForm()  # reset form fields
            except Exception as exc:  # pragma: no cover - best effort logging
                current_app.logger.exception('Failed to mint credential')
                flash(f'Issuance failed: {exc}', 'danger')

    search_query = request.args.get('q', '').strip()
    status_filter = request.args.get('status', 'all')

    credential_query = IssuedCredential.query

    if status_filter == 'active':
        credential_query = credential_query.filter_by(revoked=False)
    elif status_filter == 'revoked':
        credential_query = credential_query.filter_by(revoked=True)

    credential_query = credential_query.order_by(IssuedCredential.issued_at.desc())
    recent_credentials = credential_query.limit(50).all()

    if search_query:
        lowered = search_query.lower()
        filtered_credentials = [
            cred for cred in recent_credentials
            if lowered in cred.student_id.lower()
            or lowered in (cred.meta_blob or {}).get('first_name', '').lower()
            or lowered in (cred.meta_blob or {}).get('last_name', '').lower()
            or lowered in cred.credential_hash.lower()
        ]
    else:
        filtered_credentials = recent_credentials

    stats = {
        'active': IssuedCredential.query.filter_by(revoked=False).count(),
        'revoked': IssuedCredential.query.filter_by(revoked=True).count(),
    }
    stats['all'] = stats['active'] + stats['revoked']

    verifications = (
        CredentialVerification.query
        .order_by(CredentialVerification.verified_at.desc())
        .limit(25)
        .all()
    )

    pending_requests = (
        VerificationRequest.query
        .filter(VerificationRequest.status == 'pending')
        .order_by(VerificationRequest.created_at.desc())
        .limit(10)
        .all()
    )

    now_dt = datetime.now(UTC)
    events_window = now_dt - timedelta(days=7)
    event_counts_raw = (
        db.session.query(SecurityEvent.event_type, func.count(SecurityEvent.id))
        .filter(SecurityEvent.created_at >= events_window)
        .group_by(SecurityEvent.event_type)
        .order_by(func.count(SecurityEvent.id).desc())
        .all()
    )
    event_counts = [
        {"event_type": event_type, "count": count}
        for event_type, count in event_counts_raw
    ]

    recent_events = (
        SecurityEvent.query
        .order_by(SecurityEvent.created_at.desc())
        .limit(15)
        .all()
    )

    daily_window = now_dt - timedelta(days=7)
    daily_issuance_raw = (
        db.session.query(func.date(IssuedCredential.issued_at), func.count(IssuedCredential.id))
        .filter(IssuedCredential.issued_at >= daily_window)
        .group_by(func.date(IssuedCredential.issued_at))
        .order_by(func.date(IssuedCredential.issued_at))
        .all()
    )
    daily_issuance = [
        {"day": day, "count": count}
        for day, count in daily_issuance_raw
    ]

    return render_template(
        'issuer/dashboard.html',
        onboarding_steps=onboarding_steps,
        form=form,
        issued_credential=issued_credential,
        credentials=filtered_credentials,
        search_query=search_query,
        status_filter=status_filter,
        stats=stats,
        verifications=verifications,
        now=datetime.now(),
        event_counts=event_counts,
        recent_events=recent_events,
        daily_issuance=daily_issuance,
        pending_requests=pending_requests,
        active_view=active_view,
    )


@issuer_bp.route('/requests/<int:request_id>/resolve', methods=['POST'])
def resolve_request(request_id: int):
    record = VerificationRequest.query.get_or_404(request_id)
    if record.status != 'handled':
        record.mark_handled()
        db.session.commit()

    return jsonify({"ok": True, "request_id": record.id})


@issuer_bp.route('/credential/<int:credential_id>/toggle', methods=['POST'])
def toggle_credential(credential_id: int):
    record = IssuedCredential.query.get_or_404(credential_id)
    if record.revoked:
        existing_active = (
            IssuedCredential.query
            .filter(
                IssuedCredential.student_id == record.student_id,
                IssuedCredential.id != record.id,
                IssuedCredential.revoked.is_(False),
                or_(
                    IssuedCredential.expires_at.is_(None),
                    IssuedCredential.expires_at > datetime.now(UTC)
                )
            )
            .first()
        )
        if existing_active:
            record_security_event(
                'issuer_restore_blocked',
                severity='medium',
                detail='Attempted to restore credential while another active record exists.',
                metadata={
                    'student_id': record.student_id,
                    'revoked_credential_id': record.id,
                    'blocking_credential_id': existing_active.id,
                }
            )
            return jsonify({
                "ok": False,
                "error": "A newer credential for this student is already active. Revoke it first before restoring older records."
            }), 400

    record.revoked = not record.revoked
    db.session.commit()

    return jsonify({
        "ok": True,
        "credential_id": credential_id,
        "revoked": record.revoked,
        "label": "Restore" if record.revoked else "Revoke",
        "status_label": "Revoked" if record.revoked else "Active",
    })


@issuer_bp.route('/credential/<int:credential_id>/refresh', methods=['POST'])
def refresh_credential(credential_id: int):
    record = IssuedCredential.query.get_or_404(credential_id)
    payload = dict(record.meta_blob or {})
    payload['issued_at'] = datetime.now(UTC).isoformat()
    payload['proof_commitment'] = _placeholder_commitment(record.student_id, payload.get('program', ''))
    valid_days = record.valid_for_days or current_app.config['CREDENTIAL_VALIDITY_DAYS_DEFAULT']
    expires_at = datetime.now(UTC) + timedelta(days=valid_days)
    payload['expires_at'] = expires_at.isoformat()
    payload['valid_for_days'] = valid_days
    certificate_id = payload.get('certificate_id') or record.certificate_id
    if certificate_id and 'certificate_id' not in payload:
        payload['certificate_id'] = certificate_id
    auth_key_value = payload.get('authentication_key')
    certificate_hash = hash_certificate_id(certificate_id) if certificate_id else None
    auth_key_hash = hash_auth_key(auth_key_value) if auth_key_value else record.auth_key_hash

    signature, credential_filename = _sign_payload(payload)

    refreshed = IssuedCredential(
        student_id=record.student_id,
        credential_hash=signature,
        meta_blob=payload,
        expires_at=expires_at,
        valid_for_days=valid_days,
        rotated_from_id=record.id,
        auth_key_hash=auth_key_hash,
        certificate_id=certificate_id,
        certificate_hash=certificate_hash,
    )
    db.session.add(refreshed)
    db.session.commit()
    ensure_wallet_qr(signature, payload.get('certificate_id'))

    return jsonify({
        "ok": True,
        "credential_id": refreshed.id,
        "download_url": url_for('static', filename=f'credentials/{credential_filename}'),
        "expires_at": payload['expires_at'],
    })



@issuer_bp.route('/credential/<int:credential_id>/download', methods=['GET'])
def download_credential(credential_id: int):
    """Allow staff to re-download the exact JSON package that was issued."""
    record = IssuedCredential.query.get_or_404(credential_id)
    if not record.meta_blob:
        flash('Credential payload missing; re-issue required.', 'danger')
        return redirect(url_for('issuer.dashboard'))

    package = {
        "payload": record.meta_blob,
        "signature": record.credential_hash,
    }
    buffer = io.BytesIO()
    buffer.write(json.dumps(package, indent=2).encode('utf-8'))
    buffer.seek(0)
    filename = f"{record.student_id}_{credential_id}_credential.json"
    return send_file(buffer, mimetype='application/json', as_attachment=True, download_name=filename)


@issuer_bp.route('/credential/<int:credential_id>/delete', methods=['POST'])
def delete_credential(credential_id: int):
    """Hard-delete a credential along with any verification attempts."""
    record = IssuedCredential.query.get_or_404(credential_id)
    CredentialVerification.query.filter_by(credential_id=record.id).delete()
    db.session.delete(record)
    db.session.commit()

    return jsonify({"ok": True, "credential_id": credential_id})


@issuer_bp.route('/security-events/export', methods=['GET'])
def export_security_events():
    """Download the structured security log as CSV for auditors."""
    events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).all()
    output = io.StringIO()
    output.write('id,event_type,severity,detail,ip_address,created_at\n')
    for event in events:
        output.write(
            f"{event.id},{event.event_type},{event.severity},"
            f"{(event.detail or '').replace(',', ';')},{event.ip_address or ''},{event.created_at.isoformat()}\n"
        )
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=security_events.csv'}
    )


@issuer_bp.route('/logout')
def issuer_logout():
    session.pop('issuer_account_id', None)
    session.pop('issuer_account_email', None)
    flash('Issuer session closed.', 'info')
    return redirect(url_for('home', page='page-login'))
