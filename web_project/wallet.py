from __future__ import annotations
import os

from flask import Blueprint, abort, current_app, render_template, url_for

from web_project.model import IssuedCredential
from web_project.wallet_utils import ensure_wallet_qr

wallet_bp = Blueprint('wallet', __name__, url_prefix='/wallet')


@wallet_bp.route('/<string:credential_hash>')
def view_wallet(credential_hash: str):
    record = IssuedCredential.query.filter_by(credential_hash=credential_hash).first()
    if record is None or record.meta_blob is None:
        abort(404)

    payload = record.meta_blob or {}
    qr_relpath = f"credentials/qr/{credential_hash}.png"
    abs_path = os.path.join(current_app.static_folder, qr_relpath.replace('/', os.sep))
    if not os.path.exists(abs_path):
        qr_relpath = ensure_wallet_qr(record.credential_hash, record.certificate_id)
        abs_path = os.path.join(current_app.static_folder, qr_relpath.replace('/', os.sep))
    qr_url = url_for('static', filename=qr_relpath)
    verifier_url = url_for('home', page='page-credential')

    status = 'revoked' if record.revoked else 'active'
    return render_template(
        'wallet/view.html',
        record=record,
        payload=payload,
        wallet_qr_url=qr_url,
        verifier_url=verifier_url,
        status=status,
    )
