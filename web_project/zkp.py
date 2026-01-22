import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request, session

from web_project import db
from web_project.model import CredentialVerification, IssuedCredential
from web_project.security_events import record_security_event
from web_project.security import hash_certificate_id
from web_project.zkp_runtime import build_snarkjs_engine

UTC = timezone.utc

zkp_bp = Blueprint('zkp', __name__, url_prefix='/zkp')


def _issuer_secret() -> bytes:
    return current_app.config.get('ISSUER_SECRET', 'dev-issuer-secret').encode('utf-8')


def _nonce_commitment(proof_commitment: str, nonce: str) -> str:
    if not proof_commitment or not nonce:
        return ''
    base = f"{proof_commitment}|{nonce}"
    return hashlib.sha256(base.encode('utf-8')).hexdigest()


@zkp_bp.route('/challenge', methods=['GET'])
def issue_challenge():
    """Generates a nonce challenge for the client-side proof generator."""
    nonce = secrets.token_hex(16)
    session['zkp_nonce'] = nonce
    ttl_seconds = current_app.config.get('ZKP_NONCE_TTL_SECONDS', 120)
    session['zkp_nonce_at'] = time.time()
    return jsonify({"nonce": nonce, "expires_in": ttl_seconds})


@zkp_bp.route('/verify', methods=['POST'])
def verify_proof():
    """Temporary verification stub that validates credential signature + nonce."""
    payload = request.get_json(silent=True) or {}
    nonce = payload.get('nonce')
    credential = payload.get('credential')
    proof = payload.get('proof')
    ttl_seconds = current_app.config.get('ZKP_NONCE_TTL_SECONDS', 120)
    nonce_issued_at = session.get('zkp_nonce_at')

    if not nonce or nonce != session.get('zkp_nonce'):
        record_security_event(
            'zkp_nonce_mismatch',
            severity='warning',
            detail='Nonce missing or expired during verification.',
            metadata={'nonce_provided': bool(nonce)},
        )
        return jsonify({"ok": False, "error": "Challenge mismatch or expired."}), 400

    if not nonce_issued_at or (time.time() - nonce_issued_at) > ttl_seconds:
        record_security_event(
            'zkp_nonce_expired',
            severity='warning',
            detail='Nonce exceeded allowed lifetime before verification.',
            metadata={'ttl_seconds': ttl_seconds},
        )
        session.pop('zkp_nonce', None)
        session.pop('zkp_nonce_at', None)
        return jsonify({"ok": False, "error": "Challenge mismatch or expired."}), 400

    if not credential or 'payload' not in credential or 'signature' not in credential:
        record_security_event(
            'credential_payload_missing',
            severity='warning',
            detail='Credential payload absent in verification request.',
        )
        return jsonify({"ok": False, "error": "Credential payload missing."}), 400

    if not proof or 'nonce_commitment' not in proof:
        record_security_event(
            'proof_payload_missing',
            severity='warning',
            detail='Proof payload absent in verification request.',
        )
        return jsonify({"ok": False, "error": "Proof object missing placeholder commitment."}), 400

    signature = credential['signature']
    secret = _issuer_secret()
    payload_serialized = json_dumps(credential['payload']).encode('utf-8')
    candidates = [
        hmac.new(secret, msg=payload_serialized, digestmod=hashlib.sha256).hexdigest()
    ]

    legacy_serialized = json.dumps(credential['payload'], sort_keys=True)
    legacy_bytes = legacy_serialized.encode('utf-8')
    if legacy_bytes != payload_serialized:
        candidates.append(hmac.new(secret, msg=legacy_bytes, digestmod=hashlib.sha256).hexdigest())

    if not any(hmac.compare_digest(candidate, signature) for candidate in candidates):
        record_security_event(
            'credential_signature_invalid',
            severity='high',
            detail='Credential signature failed verification.',
        )
        return jsonify({"ok": False, "error": "Credential signature invalid."}), 400

    issued_record = IssuedCredential.query.filter_by(credential_hash=credential['signature']).first()
    if not issued_record:
        record_security_event(
            'credential_not_found',
            severity='warning',
            detail='Credential signature not present in registry.',
        )
        return jsonify({"ok": False, "error": "Credential not found in issuer registry."}), 400
    if issued_record.revoked:
        record_security_event(
            'credential_revoked_access',
            severity='medium',
            detail='Revoked credential attempted verification.',
            metadata={'credential_id': issued_record.id},
        )
        return jsonify({"ok": False, "error": "Credential has been revoked by issuer."}), 400

    cert_id = credential['payload'].get('certificate_id')
    if issued_record.certificate_hash:
        if not cert_id:
            record_security_event(
                'certificate_id_missing',
                severity='warning',
                detail='Issued credential expected certificate ID but payload lacked it.',
                metadata={'credential_id': issued_record.id},
            )
            return jsonify({"ok": False, "error": "Certificate ID missing from credential."}), 400
        if hash_certificate_id(cert_id) != issued_record.certificate_hash:
            record_security_event(
                'certificate_integrity_mismatch',
                severity='high',
                detail='Credential certificate hash mismatch during verification.',
                metadata={'credential_id': issued_record.id},
            )
            return jsonify({"ok": False, "error": "Certificate integrity mismatch."}), 400

    proof_commitment = credential['payload'].get('proof_commitment')
    expected_commitment = _nonce_commitment(proof_commitment, nonce)

    if not expected_commitment or not hmac.compare_digest(expected_commitment, proof['nonce_commitment']):
        record_security_event(
            'zk_commitment_invalid',
            severity='medium',
            detail='Provided proof commitment did not match nonce.',
            metadata={'credential_id': issued_record.id},
        )
        return jsonify({"ok": False, "error": "Placeholder ZK commitment invalid."}), 400

    zk_bundle = proof.get('zk')
    if zk_bundle:
        engine = build_snarkjs_engine()
        if not engine.available:
            record_security_event(
                'zk_engine_unavailable',
                severity='warning',
                detail='Browser provided zk proof but verifier not configured.',
            )
            return jsonify({"ok": False, "error": "Verifier not configured for real proofs."}), 400

        proof_payload = zk_bundle.get('proof')
        public_signals = zk_bundle.get('publicSignals')
        if not proof_payload or public_signals is None:
            record_security_event(
                'zk_payload_missing',
                severity='warning',
                detail='zk proof bundle missing proof or publicSignals.',
            )
            return jsonify({"ok": False, "error": "Proof bundle incomplete."}), 400

        ok, reason = engine.verify(proof_payload, public_signals)
        if not ok:
            record_security_event(
                'zk_real_proof_invalid',
                severity='high',
                detail='snarkjs verification failed.',
                metadata={'error': reason},
            )
            return jsonify({"ok": False, "error": "Zero-knowledge proof invalid."}), 400

    ttl_seconds = current_app.config.get('VERIFICATION_TTL_SECONDS', 900)
    expires_at = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
    verification_token = secrets.token_hex(16)

    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    verification_record = CredentialVerification(
        credential_id=issued_record.id,
        student_id=credential['payload'].get('student_id'),
        credential_hash=credential['signature'],
        session_token=verification_token,
        expires_at=expires_at,
        ip_address=client_ip,
    )
    db.session.add(verification_record)
    db.session.commit()

    session['credential_verified'] = {
        'student_id': credential['payload'].get('student_id'),
        'first_name': credential['payload'].get('first_name'),
        'last_name': credential['payload'].get('last_name'),
        'program': credential['payload'].get('program'),
        'certificate_id': cert_id,
        'token': verification_token,
        'expires_at': expires_at.isoformat(),
        'ip_address': client_ip,
    }
    session.pop('zkp_nonce', None)
    session.pop('zkp_nonce_at', None)

    return jsonify({"ok": True, "student_id": credential['payload'].get('student_id')})

def json_dumps(data):
    """Consistent JSON serialization to guarantee signature stability."""
    import json

    return json.dumps(data, sort_keys=True, separators=(',', ':'))
