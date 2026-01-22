from __future__ import annotations

import json
import os

import qrcode
from flask import current_app, url_for


def ensure_wallet_qr(signature: str, certificate_id: str | None) -> str:
    """Persist (or refresh) the QR code image for a credential wallet.

    Returns the relative path under the static folder.
    """
    wallet_url = url_for('wallet.view_wallet', credential_hash=signature, _external=True)
    payload = {
        "wallet_url": wallet_url,
        "credential_hash": signature,
    }
    if certificate_id:
        payload["certificate_id"] = certificate_id

    qr_dir = current_app.config['CREDENTIAL_QR_DIR']
    os.makedirs(qr_dir, exist_ok=True)
    filepath = os.path.join(qr_dir, f"{signature}.png")

    qr_code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=2)
    qr_code.add_data(json.dumps(payload, sort_keys=True))
    qr_code.make(fit=True)
    qr_code.make_image(fill_color="black", back_color="white").save(filepath)

    rel_path = os.path.relpath(filepath, current_app.static_folder)
    return rel_path.replace('\\', '/')
