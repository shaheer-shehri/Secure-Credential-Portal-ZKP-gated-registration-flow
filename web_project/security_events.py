"""Helpers for recording structured security events."""
from __future__ import annotations

from typing import Any, Optional

from flask import current_app, request

from web_project import db
from web_project.model import SecurityEvent


def record_security_event(
    event_type: str,
    *,
    severity: str = "info",
    detail: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """Persist a security event and mirror it to the application logger."""
    if not event_type:
        raise ValueError("event_type is required")

    ip_address = None
    if request:
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)

    event = SecurityEvent(
        event_type=event_type,
        detail=detail,
        severity=severity,
        ip_address=ip_address,
        context_blob=metadata,
    )
    db.session.add(event)
    db.session.commit()

    logger = current_app.logger
    logger.info(
        "SECURITY_EVENT",
        extra={
            "event_type": event_type,
            "severity": severity,
            "detail": detail,
            "context_blob": metadata or {},
            "ip_address": ip_address,
        },
    )
