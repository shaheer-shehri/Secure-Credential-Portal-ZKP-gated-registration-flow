from datetime import datetime, timezone
from typing import Optional

from web_project import db
from flask_login import UserMixin
from web_project import bcrypt

UTC = timezone.utc

class User(db.Model, UserMixin):
    __tablename__ = 'user'


    id = db.Column(db.Integer(), primary_key=True)
    student_id = db.Column(db.String(30), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    image_path = db.Column(db.String(255), nullable=False)

    section = db.Column(db.String(50), nullable=True)
    counselor_email = db.Column(db.String(100), nullable=False)
    is_issuer = db.Column(db.Boolean(), nullable=False, default=False)

    @property
    def password(self):
        return self.password_hash

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password(self, attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password)

    def get_id(self):
        return (self.id)


def _as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class IssuedCredential(db.Model):
    """Tracks every credential minted by the issuer service."""

    __tablename__ = 'issued_credential'

    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=True)
    student_id = db.Column(db.String(30), nullable=False)
    credential_hash = db.Column(db.String(128), unique=True, nullable=False)
    issued_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    valid_for_days = db.Column(db.Integer(), nullable=False, default=30)
    revoked = db.Column(db.Boolean(), default=False, nullable=False)
    meta_blob = db.Column(db.JSON(), nullable=True)
    auth_key_hash = db.Column(db.String(128), nullable=True)
    certificate_id = db.Column(db.String(64), nullable=True)
    certificate_hash = db.Column(db.String(128), nullable=True)
    rotated_from_id = db.Column(db.Integer(), db.ForeignKey('issued_credential.id'), nullable=True)

    parent_credential = db.relationship('IssuedCredential', remote_side=[id], backref='rotations', lazy=True)

    user = db.relationship('User', backref='credentials', lazy=True)

    def mark_revoked(self):
        """Helper toggled when admins revoke a credential."""
        self.revoked = True

    def is_expired(self):
        expiry = _as_utc(self.expires_at)
        now = datetime.now(UTC)
        return expiry is not None and expiry < now


class CredentialVerification(db.Model):
    """Persists each credential proof event for signup gating."""

    __tablename__ = 'credential_verification'

    id = db.Column(db.Integer(), primary_key=True)
    credential_id = db.Column(db.Integer(), db.ForeignKey('issued_credential.id'), nullable=True)
    student_id = db.Column(db.String(30), nullable=False)
    credential_hash = db.Column(db.String(128), nullable=False)
    session_token = db.Column(db.String(64), unique=True, nullable=False)
    verified_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    consumed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)

    credential = db.relationship('IssuedCredential', backref='verifications', lazy=True)

    def is_active(self):
        now = datetime.now(UTC)
        expiry = _as_utc(self.expires_at)
        consumed = _as_utc(self.consumed_at)
        return consumed is None and expiry is not None and expiry > now

    def consume(self):
        self.consumed_at = datetime.now(UTC)

    def verified_at_utc(self) -> Optional[datetime]:
        return _as_utc(self.verified_at)


class SecurityEvent(db.Model):
    """Audit log for suspicious or notable security-related actions."""

    __tablename__ = 'security_event'

    id = db.Column(db.Integer(), primary_key=True)
    event_type = db.Column(db.String(64), nullable=False)
    detail = db.Column(db.String(255), nullable=True)
    severity = db.Column(db.String(16), nullable=False, default='info')
    ip_address = db.Column(db.String(64), nullable=True)
    context_blob = db.Column(db.JSON(), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)

    def as_dict(self):
        return {
            'id': self.id,
            'event_type': self.event_type,
            'detail': self.detail,
            'severity': self.severity,
            'ip_address': self.ip_address,
            'context_blob': self.context_blob,
            'created_at': self.created_at.astimezone(UTC).isoformat(),
        }


class VerificationRequest(db.Model):
    """Stores student-submitted verification/minting requests."""

    __tablename__ = 'verification_request'

    id = db.Column(db.Integer(), primary_key=True)
    student_id = db.Column(db.String(30), nullable=False)
    section = db.Column(db.String(50), nullable=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    notes = db.Column(db.Text(), nullable=True)
    status = db.Column(db.String(20), nullable=False, default='pending')
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    handled_at = db.Column(db.DateTime(timezone=True), nullable=True)

    def mark_handled(self):
        self.status = 'handled'
        self.handled_at = datetime.now(UTC)



class IssuerAccount(db.Model):
    """Faculty/staff accounts that can unlock the issuer console."""

    __tablename__ = 'issuer_account'

    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    @property
    def password(self):
        return self.password_hash

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password(self, attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password)
