"""Security helper utilities for credential signing and hashing."""
from __future__ import annotations

import hashlib
from flask import current_app


def _pepper(config_key: str, default: str) -> str:
    return current_app.config.get(config_key, default)


def hash_auth_key(value: str) -> str:
    """Return a deterministic hash of the student-provided authentication key."""
    salted = f"{value}|{_pepper('AUTH_KEY_PEPPER', 'dev-auth-pepper')}"
    return hashlib.sha256(salted.encode('utf-8')).hexdigest()


def hash_certificate_id(value: str) -> str:
    """Hash the certificate identifier for storage/lookup."""
    salted = f"{value}|{_pepper('CERTIFICATE_HASH_PEPPER', 'dev-cert-pepper')}"
    return hashlib.sha256(salted.encode('utf-8')).hexdigest()
