from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from dotenv import load_dotenv
import os
import warnings

load_dotenv()


def _secret_from_env(key: str, fallback: str) -> str:
    """Load sensitive config with a safe fallback for local dev."""
    value = os.environ.get(key)
    if value:
        return value
    warnings.warn(f"Environment variable {key} is not set; using insecure fallback.")
    return fallback

app = Flask(__name__)
app.config['SECRET_KEY'] = _secret_from_env('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///studentData_db.sqlite3'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ISSUER_SECRET'] = _secret_from_env('ISSUER_SECRET', 'dev-issuer-secret')
app.config['CREDENTIAL_VALIDITY_DAYS_DEFAULT'] = int(os.environ.get('CREDENTIAL_VALIDITY_DAYS', 30))
app.config['AUTH_KEY_PEPPER'] = os.environ.get('AUTH_KEY_PEPPER', 'dev-auth-pepper')
app.config['CERTIFICATE_HASH_PEPPER'] = os.environ.get('CERTIFICATE_HASH_PEPPER', 'dev-cert-pepper')

# Flask-Mail Configuration - USE ENVIRONMENT VARIABLES!
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.googlemail.com') # Example: Gmail
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')


app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME']) # sending email

app.config['ADMIN_EMAIL'] = os.environ.get('ADMIN_EMAIL', 'admin@example.com') # receiving email
if not (app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD']):
    app.config['MAIL_SUPPRESS_SEND'] = True

from flask_mail import Mail
mail = Mail(app)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'home'

app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

app.config['ZKP_ASSETS_DIR'] = os.path.join(app.static_folder, 'zkp')
os.makedirs(app.config['ZKP_ASSETS_DIR'], exist_ok=True)
app.config['ZKP_VKEY_PATH'] = os.environ.get('ZKP_VKEY_PATH', os.path.join(app.config['ZKP_ASSETS_DIR'], 'verification_key.json'))
app.config['SNARKJS_CMD'] = os.environ.get('SNARKJS_CMD', '').strip()
app.config['CREDENTIAL_QR_DIR'] = os.path.join(app.static_folder, 'credentials', 'qr')
os.makedirs(app.config['CREDENTIAL_QR_DIR'], exist_ok=True)
app.config['ZKP_NONCE_TTL_SECONDS'] = int(os.environ.get('ZKP_NONCE_TTL_SECONDS', 120))

from web_project.model import User
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from web_project.admin import issuer_bp
from web_project.zkp import zkp_bp
from web_project.wallet import wallet_bp
from web_project import routes

app.register_blueprint(issuer_bp)
app.register_blueprint(zkp_bp)
app.register_blueprint(wallet_bp)