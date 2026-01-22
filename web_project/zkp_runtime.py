"""Helpers for detecting and verifying zero-knowledge proof assets."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from flask import current_app, url_for


class SnarkjsProofEngine:
    """Thin wrapper that shells out to snarkjs groth16 verify."""

    def __init__(self, vkey_path: Path, command: Optional[str]):
        self.vkey_path = vkey_path
        self.command = shlex.split(command) if command else []
        self.available = self.vkey_path.exists() and bool(self.command)

    def verify(self, proof: Dict[str, Any], public_signals: Any) -> Tuple[bool, Optional[str]]:
        if not self.available:
            return False, 'SnarkJS verifier not configured.'

        proof_file = tempfile.NamedTemporaryFile('w', delete=False, suffix='.json')
        signals_file = tempfile.NamedTemporaryFile('w', delete=False, suffix='.json')

        try:
            json.dump(proof, proof_file)
            proof_file.flush()
            json.dump(public_signals, signals_file)
            signals_file.flush()

            cmd = self.command + [
                'groth16',
                'verify',
                str(self.vkey_path),
                signals_file.name,
                proof_file.name,
            ]

            completed = subprocess.run(  # noqa: S603,S607 - intentional shell-out
                cmd,
                check=False,
                capture_output=True,
                text=True,
                cwd=current_app.root_path,
            )
            if completed.returncode != 0:
                message = completed.stderr.strip() or completed.stdout.strip() or 'snarkjs verification failed.'
                return False, message
            return True, None
        finally:
            try:
                os.unlink(proof_file.name)
            except OSError:
                pass
            try:
                os.unlink(signals_file.name)
            except OSError:
                pass


def build_snarkjs_engine() -> SnarkjsProofEngine:
    app = current_app
    vkey_path = Path(app.config['ZKP_VKEY_PATH'])
    command = app.config.get('SNARKJS_CMD')
    return SnarkjsProofEngine(vkey_path, command)


def runtime_manifest() -> Dict[str, Any]:
    app = current_app
    assets_dir = Path(app.static_folder) / 'zkp'
    wasm_path = assets_dir / 'credential.wasm'
    zkey_path = assets_dir / 'credential.zkey'

    browser_ready = wasm_path.exists() and zkey_path.exists()
    manifest = {
        'browserProver': browser_ready,
        'proofType': 'groth16' if browser_ready else 'placeholder',
        'assets': {},
    }
    if browser_ready:
        manifest['assets'] = {
            'wasm': url_for('static', filename='zkp/credential.wasm'),
            'zkey': url_for('static', filename='zkp/credential.zkey'),
        }
    manifest['verifierConfigured'] = Path(app.config['ZKP_VKEY_PATH']).exists() and bool(app.config.get('SNARKJS_CMD'))
    return manifest
