"""CLI harness that exercises the zero-knowledge credential flow end-to-end.

Usage:
    python scripts/zk_flow_demo.py

This script will:
    1. Create (or refresh) a demo credential with a valid HMAC signature.
    2. Call the /zkp/challenge endpoint to obtain a nonce.
    3. Build the placeholder proof commitment used by the browser.
    4. POST the credential + proof to /zkp/verify and print the response.
"""

from __future__ import annotations

import json
import hashlib
import hmac
from datetime import datetime, timezone
UTC = timezone.utc
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_project import app, db  # type: ignore  # pylint: disable=wrong-import-position
from web_project.admin import _placeholder_commitment  # type: ignore  # pylint: disable=wrong-import-position
from web_project.model import IssuedCredential  # type: ignore  # pylint: disable=wrong-import-position
from web_project.security import hash_auth_key, hash_certificate_id  # type: ignore  # pylint: disable=wrong-import-position


def _sign_payload(payload: dict, secret: str) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), serialized, hashlib.sha256).hexdigest()


def _build_placeholder_proof(proof_commitment: str, nonce: str) -> str:
    if not proof_commitment or not nonce:
        raise ValueError("Proof commitment and nonce are required to build the placeholder proof")
    material = f"{proof_commitment}|{nonce}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def ensure_demo_credential() -> dict:
    """Create a deterministic credential the verifier will accept."""
    with app.app_context():
        db.create_all()
        commitment = _placeholder_commitment("DEMO-S123456", "Zero Knowledge Lab")
        auth_key = "demo-shared-secret"
        certificate_id = "DEMO-CERT-001"
        certificate_hash = hash_certificate_id(certificate_id)
        payload = {
            "student_id": "DEMO-S123456",
            "first_name": "Aaliya",
            "last_name": "Rizvi",
            "program": "Zero Knowledge Lab",
            "issued_at": datetime.now(UTC).isoformat(),
            "biometric_verified": True,
            "issuer_notes": "Automatically generated demo credential.",
            "id_proof_path": "issuer/demo_id.jpg",
            "selfie_path": "issuer/demo_selfie.jpg",
            "university": "NUST SEECS",
            "proof_commitment": commitment,
            "face_evidence": {
                "status": "completed",
                "match": True,
                "distance": 0.3521,
                "confidence": "high",
            },
            "certificate_id": certificate_id,
            "authentication_key": auth_key,
        }

        secret = app.config.get("ISSUER_SECRET", "dev-issuer-secret")
        signature = _sign_payload(payload, secret)

        record = IssuedCredential.query.filter_by(credential_hash=signature).first()
        if record is None:
            record = IssuedCredential(
                student_id=payload["student_id"],
                credential_hash=signature,
                meta_blob=payload,
            )
        else:
            record.student_id = payload["student_id"]
            record.meta_blob = payload
            record.revoked = False

        record.issued_at = datetime.now(UTC)
        record.auth_key_hash = hash_auth_key(auth_key)
        record.certificate_id = certificate_id
        record.certificate_hash = certificate_hash
        db.session.add(record)
        db.session.commit()

        return {"payload": payload, "signature": signature}


def run_demo() -> dict:
    credential = ensure_demo_credential()

    with app.test_client() as client:
        challenge_resp = client.get("/zkp/challenge")
        if challenge_resp.status_code != 200:
            raise RuntimeError(f"Challenge endpoint failed: {challenge_resp.status_code} {challenge_resp.data}")

        challenge_data = challenge_resp.get_json()
        nonce = challenge_data["nonce"]
        proof = {"nonce_commitment": _build_placeholder_proof(credential["payload"]["proof_commitment"], nonce)}

        verify_resp = client.post(
            "/zkp/verify",
            json={
                "nonce": nonce,
                "credential": credential,
                "proof": proof,
            },
        )
        verify_data = verify_resp.get_json()

        if verify_resp.status_code != 200 or not verify_data.get("ok"):
            raise RuntimeError(f"Verification failed: {verify_resp.status_code} {verify_data}")

        return {
            "challenge": challenge_data,
            "verification": verify_data,
        }


if __name__ == "__main__":
    result = run_demo()
    print("Challenge ->", result["challenge"])
    print("Verification ->", result["verification"])
