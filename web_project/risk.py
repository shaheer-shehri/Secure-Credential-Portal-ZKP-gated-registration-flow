"""Adaptive risk scoring helpers for signup gating."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass
class RiskAssessment:
    score: int
    reasons: list[str]

    @property
    def level(self) -> str:
        if self.score >= 70:
            return "high"
        if self.score >= 40:
            return "medium"
        return "low"


RISK_THRESHOLDS = {
    "verification_age_minutes": (5, 20),  # (medium, high)
    "recent_failures": (1, 3),
}


def assess_signup_risk(
    *,
    minutes_since_verification: float,
    recent_failure_events: int,
    verification_ip: str | None,
    request_ip: str | None,
) -> RiskAssessment:
    score = 0
    reasons: list[str] = []

    if minutes_since_verification > RISK_THRESHOLDS["verification_age_minutes"][1]:
        score += 50
        reasons.append("Verification token is stale; requires re-proof.")
    elif minutes_since_verification > RISK_THRESHOLDS["verification_age_minutes"][0]:
        score += 20
        reasons.append("Verification happened several minutes ago; moderate risk.")

    if recent_failure_events >= RISK_THRESHOLDS["recent_failures"][1]:
        score += 40
        reasons.append("Multiple security events originated from this client recently.")
    elif recent_failure_events >= RISK_THRESHOLDS["recent_failures"][0]:
        score += 15
        reasons.append("Recent warning events detected for this IP.")

    if verification_ip and request_ip and verification_ip != request_ip:
        score += 30
        reasons.append("Signup IP differs from verified IP.")

    return RiskAssessment(score=score, reasons=reasons)
