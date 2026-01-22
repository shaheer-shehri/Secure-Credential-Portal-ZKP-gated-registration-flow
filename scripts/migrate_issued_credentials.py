"""Upgrade script to backfill new issuer credential columns.

Run:
    python scripts/migrate_issued_credentials.py

Adds the latest schema columns and fills any missing expiry metadata.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_CANDIDATES = [
    ROOT / 'studentData_db.sqlite3',
    ROOT / 'instance' / 'studentData_db.sqlite3',
]


def column_map(cursor, table: str) -> dict[str, dict]:
    cursor.execute(f"PRAGMA table_info({table})")
    return {row[1]: row for row in cursor.fetchall()}


def ensure_column(cursor, table: str, column: str, ddl: str) -> None:
    if column in column_map(cursor, table):
        return
    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def backfill_expiry(cursor) -> None:
    cursor.execute(
        "SELECT id, issued_at, expires_at, valid_for_days FROM issued_credential"
    )
    rows = cursor.fetchall()
    for record_id, issued_at, expires_at, valid_for_days in rows:
        if valid_for_days is None:
            valid_for_days = 30
        if expires_at:
            continue
        expires_value: str | None = None
        if issued_at:
            try:
                expires_value = _compute_expiry(issued_at, valid_for_days)
            except ValueError:
                expires_value = None
        cursor.execute(
            "UPDATE issued_credential SET expires_at = ?, valid_for_days = ? WHERE id = ?",
            (expires_value, valid_for_days, record_id),
        )


def _compute_expiry(issued_at: str, valid_days: int) -> str:
    ts = issued_at
    if ts.endswith('Z'):
        ts = ts.replace('Z', '+00:00')
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError as exc:  # fallback for sqlite default str
        try:
            dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            raise exc
    expires = dt + timedelta(days=valid_days or 30)
    return expires.isoformat() + ('Z' if expires.tzinfo is None else '')


def locate_db() -> Path:
    for path in DB_CANDIDATES:
        if path.exists():
            return path
    raise SystemExit('Database not found in expected locations. Checked: ' + ', '.join(str(p) for p in DB_CANDIDATES))


def main() -> None:
    db_path = locate_db()
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        ensure_column(cursor, 'issued_credential', 'expires_at', 'expires_at DATETIME')
        ensure_column(cursor, 'issued_credential', 'valid_for_days', 'valid_for_days INTEGER DEFAULT 30')
        ensure_column(cursor, 'issued_credential', 'rotated_from_id', 'rotated_from_id INTEGER')
        ensure_column(cursor, 'issued_credential', 'auth_key_hash', 'auth_key_hash TEXT')
        ensure_column(cursor, 'issued_credential', 'certificate_id', 'certificate_id TEXT')
        ensure_column(cursor, 'issued_credential', 'certificate_hash', 'certificate_hash TEXT')
        ensure_column(cursor, 'credential_verification', 'ip_address', 'ip_address TEXT')
        backfill_expiry(cursor)
        conn.commit()
        print('Migration complete.')
    finally:
        conn.close()


if __name__ == '__main__':
    main()
