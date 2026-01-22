import os

import pytest

from web_project import app, db


@pytest.fixture()
def test_app(tmp_path):
    """Configure the Flask app for isolated tests."""
    uploads = tmp_path / 'uploads'
    qr_dir = tmp_path / 'qr'
    static_dir = tmp_path / 'static'
    database_path = tmp_path / 'test.sqlite'

    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI=f'sqlite:///{database_path}',
        WTF_CSRF_ENABLED=False,
        MAIL_SUPPRESS_SEND=True,
        SECRET_KEY='test-secret-key',
        ISSUER_SECRET='test-issuer-secret',
        SERVER_NAME='localhost',
        UPLOAD_FOLDER=str(uploads),
        CREDENTIAL_QR_DIR=str(qr_dir),
    )

    app.static_folder = str(static_dir)
    os.makedirs(app.static_folder, exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['CREDENTIAL_QR_DIR'], exist_ok=True)

    app.config['ZKP_ASSETS_DIR'] = os.path.join(app.static_folder, 'zkp')
    os.makedirs(app.config['ZKP_ASSETS_DIR'], exist_ok=True)
    app.config['ZKP_VKEY_PATH'] = str(tmp_path / 'verification_key.json')
    app.config['SNARKJS_CMD'] = ''
    app.config['ZKP_NONCE_TTL_SECONDS'] = 120

    ctx = app.app_context()
    ctx.push()
    db.session.remove()
    db.drop_all()
    db.create_all()

    yield app

    db.session.remove()
    db.drop_all()
    ctx.pop()


@pytest.fixture()
def client(test_app):
    return test_app.test_client()
