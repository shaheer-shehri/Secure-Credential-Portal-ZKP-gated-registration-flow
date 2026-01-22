import base64
import hashlib
import hmac
import io
import json
from datetime import datetime, timedelta, UTC

import pytest

from web_project import db
from web_project.model import CredentialVerification, IssuedCredential, User
from web_project.security import hash_auth_key, hash_certificate_id


def _mint_local_credential(app, *, student_id='S123456', auth_key_plain='secret-key'):
    payload = {
        'student_id': student_id,
        'first_name': 'Test',
        'last_name': 'User',
        'program': 'CS',
        'issued_at': datetime.now(UTC).isoformat(),
        'proof_commitment': 'commitment123',
        'certificate_id': 'cert-' + student_id,
    }
    secret = app.config['ISSUER_SECRET'].encode('utf-8')
    serialized = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    signature = hmac.new(secret, serialized, hashlib.sha256).hexdigest()

    credential = IssuedCredential(
        student_id=student_id,
        credential_hash=signature,
        meta_blob=payload,
        valid_for_days=30,
        auth_key_hash=hash_auth_key(auth_key_plain),
        certificate_id=payload['certificate_id'],
        certificate_hash=hash_certificate_id(payload['certificate_id']),
    )
    db.session.add(credential)
    db.session.commit()
    return payload, signature, credential, auth_key_plain


def _nonce_commitment(proof_commitment: str, nonce: str) -> str:
    material = f"{proof_commitment}|{nonce}".encode('utf-8')
    return hashlib.sha256(material).hexdigest()


def test_zkp_nonce_expiry(client, test_app):
    payload, signature, _record, _ = _mint_local_credential(test_app)

    challenge = client.get('/zkp/challenge').get_json()
    nonce = challenge['nonce']
    with client.session_transaction() as session:
        session['zkp_nonce_at'] -= 10_000  # force expiry regardless of configured TTL

    response = client.post(
        '/zkp/verify',
        json={
            'nonce': nonce,
            'credential': {'payload': payload, 'signature': signature},
            'proof': {'nonce_commitment': _nonce_commitment(payload['proof_commitment'], nonce)},
        },
    )

    assert response.status_code == 400
    body = response.get_json()
    assert body['ok'] is False


def test_zkp_verify_success_sets_session(client, test_app):
    payload, signature, credential, _ = _mint_local_credential(test_app)

    nonce = client.get('/zkp/challenge').get_json()['nonce']
    data = {
        'nonce': nonce,
        'credential': {'payload': payload, 'signature': signature},
        'proof': {'nonce_commitment': _nonce_commitment(payload['proof_commitment'], nonce)},
    }

    response = client.post('/zkp/verify', json=data)
    assert response.status_code == 200
    assert response.get_json()['ok'] is True
    assert CredentialVerification.query.count() == 1

    with client.session_transaction() as session:
        snapshot = session.get('credential_verified')
        assert snapshot['student_id'] == payload['student_id']
        assert snapshot['certificate_id'] == payload['certificate_id']


def test_signup_flow_consumes_verification(client, test_app):
    payload, signature, credential, auth_key_plain = _mint_local_credential(test_app, auth_key_plain='signup-key')
    verification = CredentialVerification(
        credential_id=credential.id,
        student_id=payload['student_id'],
        credential_hash=signature,
        session_token='tok-123',
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    db.session.add(verification)
    db.session.commit()

    with client.session_transaction() as session:
        session['credential_verified'] = {
            'student_id': payload['student_id'],
            'first_name': payload['first_name'],
            'last_name': payload['last_name'],
            'token': verification.session_token,
            'ip_address': '127.0.0.1',
        }

    face_b64 = base64.b64encode(b'test-image-bytes').decode('ascii')
    form_data = {
        'student_id': payload['student_id'],
        'first_name': payload['first_name'],
        'last_name': payload['last_name'],
        'auth_key': auth_key_plain,
        'email': 'test@example.com',
        'section': 'A06[ADV]/01',
        'counselor_email': 'Mariam.AlDhaheri1@actvet.gov.ae',
        'password': 'SuperSecure!1',
        'password_confirm': 'SuperSecure!1',
        'face_image_base64': f'data:image/png;base64,{face_b64}',
    }

    response = client.post('/signup', data=form_data)
    assert response.status_code == 302
    assert User.query.filter_by(email='test@example.com').count() == 1

    db.session.refresh(verification)
    assert verification.consumed_at is not None


def test_issuer_mint_creates_credential(client, test_app, monkeypatch):
    def fake_diagnostics(*_args, **_kwargs):
        return {
            'status': 'completed',
            'match': True,
            'distance': 0.42,
            'confidence': 'high',
        }

    monkeypatch.setattr('web_project.admin._face_match_diagnostics', fake_diagnostics)
    monkeypatch.setattr('web_project.admin.ensure_wallet_qr', lambda *args, **kwargs: 'credentials/qr/fake.png')

    with client.session_transaction() as session:
        session['issuer_account_id'] = 1
        session['issuer_account_email'] = 'issuer@example.com'

    selfie_b64 = base64.b64encode(b'selfie-bytes').decode('ascii')
    data = {
        'student_id': 'S654321',
        'first_name': 'Issuer',
        'last_name': 'Tester',
        'program': 'ECE',
        'valid_days': '30',
        'issuer_notes': 'Test issuance',
        'selfie_image_base64': f'data:image/png;base64,{selfie_b64}',
    }
    file_storage = {
        'id_document': (io.BytesIO(b'fake-image'), 'id.png'),
    }
    data.update(file_storage)

    response = client.post('/issuer/dashboard', data=data, content_type='multipart/form-data')

    assert response.status_code == 200
    assert b'Credential minted successfully' in response.data
    assert IssuedCredential.query.count() == 1