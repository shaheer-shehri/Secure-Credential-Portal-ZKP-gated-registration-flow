"""Automated harness that runs security regression attacks.

Usage:
    python scripts/security_attack_lab.py [--iterations COUNT]

The script will exercise (per iteration):
    1. Certificate tampering during /zkp/verify (expect rejection + audit event).
    2. Signup attempt without prerequisite verification (expect redirect + audit event).
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys

from flask import Response

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_project import app, db  # type: ignore  # pylint: disable=wrong-import-position
from web_project.model import SecurityEvent  # type: ignore  # pylint: disable=wrong-import-position
from scripts.zk_flow_demo import (  # type: ignore  # pylint: disable=wrong-import-position
    ensure_demo_credential,
    _build_placeholder_proof,
)


def _latest_event(event_type: str) -> SecurityEvent | None:
    with app.app_context():
        return (
            SecurityEvent.query.filter_by(event_type=event_type)
            .order_by(SecurityEvent.id.desc())
            .first()
        )


def _decode(resp: Response) -> dict:
    try:
        return json.loads(resp.data.decode("utf-8"))
    except Exception:  # pragma: no cover - diagnostics only
        return {"raw": resp.data.decode("utf-8", errors="ignore")}


def run_commitment_tamper_attack() -> dict:
    """Attempt to tamper with the proof commitment during verification."""
    credential = ensure_demo_credential()
    with app.test_client() as client:
        challenge = client.get("/zkp/challenge")
        challenge_json = challenge.get_json()
        nonce = challenge_json["nonce"]
        proof = {
            "nonce_commitment": _build_placeholder_proof(
                credential["payload"]["proof_commitment"],
                nonce,
            )
        }
        malicious = copy.deepcopy(credential)
        proof["nonce_commitment"] = "deadbeef" * 8  # invalid commitment
        verify_resp = client.post(
            "/zkp/verify",
            json={
                "nonce": nonce,
                "credential": malicious,
                "proof": proof,
            },
        )

    event = _latest_event("zk_commitment_invalid")
    return {
        "attack": "zk_commitment_tamper",
        "status_code": verify_resp.status_code,
        "response": _decode(verify_resp),
        "event_logged": bool(event),
        "event_id": event.id if event else None,
    }


def run_signup_bypass_attack() -> dict:
    """Attempt to hit /signup without running verifier first."""
    with app.test_client() as client:
        resp = client.post("/signup", data={}, follow_redirects=False)

    event = _latest_event("signup_without_verification")
    return {
        "attack": "signup_without_verification",
        "status_code": resp.status_code,
        "location": resp.headers.get("Location"),
        "event_logged": bool(event),
        "event_id": event.id if event else None,
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run regression attacks repeatedly.")
    parser.add_argument(
        "-i",
        "--iterations",
        "--count",
        dest="iterations",
        type=int,
        default=5,
        metavar="COUNT",
        help="Number of times to repeat the attack suite (default: 5).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv or [])
    with app.app_context():
        db.create_all()
    attempts = []
    for round_id in range(1, args.iterations + 1):
        commit = run_commitment_tamper_attack()
        commit["round"] = round_id
        signup = run_signup_bypass_attack()
        signup["round"] = round_id
        attempts.extend([commit, signup])

    blocked = sum(1 for result in attempts if result.get("event_logged"))
    summary = {
        "iterations": args.iterations,
        "total_attempts": len(attempts),
        "blocked_attempts": blocked,
        "block_rate": blocked / len(attempts) if attempts else 0.0,
    }

    # Provide structured evidence that defenses stay effective across repeated attacks.
    print(f"Applied attacks: {summary['total_attempts']}")
    print(f"Successful defenses: {summary['blocked_attempts']}")
    print(json.dumps({"results": attempts, "summary": summary}, indent=2))


if __name__ == "__main__":
    main(sys.argv[1:])
