# Secure Credential Portal

Secure Credential Portal is a Flask-based credential issuance and student self-service platform designed around **strong identity verification**, **issuer-controlled credentials**, and a **zero-knowledge proof (ZKP)–gated registration flow**.

The system enables issuers to mint cryptographically protected credentials containing per-student authentication keys and certificate identifiers. Students must successfully complete a verification challenge before registration is allowed. The platform is built with auditability, adaptive risk controls, and extensibility in mind.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Environment Configuration](#environment-configuration)
- [Database Initialization](#database-initialization)
- [Database Migration](#database-migration)
- [Running the Application](#running-the-application)
- [Development Seed Issuer Account](#development-seed-issuer-account)
- [Zero-Knowledge Demo Harness](#zero-knowledge-demo-harness)
- [Automated Attack Lab](#automated-attack-lab)
- [Student Credential Wallet](#student-credential-wallet)
- [Issuer Analytics and Adaptive Risk](#issuer-analytics-and-adaptive-risk)
- [Real Zero-Knowledge Verification (Optional)](#real-zero-knowledge-verification-optional)
- [Authentication Key and Certificate Workflow](#authentication-key-and-certificate-workflow)
- [Troubleshooting](#troubleshooting)
- [Useful Scripts](#useful-scripts)
- [Automated Tests](#automated-tests)

---

## Overview

Secure Credential Portal combines biometric-assisted credential issuance, issuer dashboards, and a zero-knowledge verification gateway to ensure that only verified students can complete registration.

Biometric matching occurs **only during issuer credential minting**. Webcam captures during student signup are stored securely for counselor review and are not automatically matched. The user interface and reporting flows reflect this separation.

---

## Key Features

- Issuer dashboard with document uploads, face diagnostics, and credential minting
- Deterministic credential packages signed via HMAC
- Zero-knowledge challenge/response flow (`/zkp/challenge`, `/zkp/verify`) gating signup
- Shareable student credential wallet with QR code
- Per-student authentication keys and certificate IDs hashed using configurable peppers
- Issuer analytics dashboard with exportable security logs
- Adaptive risk engine blocking suspicious signups
- Integrated workflows for signup, complaints, leave, and password resets

---

## System Requirements

- Python 3.10 or higher
- SQLite (default) or any SQLAlchemy-supported database
- System dependencies for `dlib` / `face_recognition`
  - CMake
  - Visual C++ Build Tools (Windows)
- Recommended: Python virtual environment

---

## Installation

Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
## Environment Configuration
Create a .env file from the provided example and populate all required secrets:

powershell
Copy code
Copy-Item .env.example .env
notepad .env
Required Environment Variables
env
Copy code
# Flask
  SECRET_KEY=change_me

# Issuer signing
  ISSUER_SECRET=change_me

# Credential hashing peppers
  AUTH_KEY_PEPPER=change_me
  CERTIFICATE_HASH_PEPPER=change_me

# Mail configuration
  MAIL_SERVER=smtp.example.com
  MAIL_PORT=587
MAIL_USE_TLS=true
  MAIL_USERNAME=example@example.com
  MAIL_PASSWORD=app_password_here
  MAIL_DEFAULT_SENDER=example@example.com

# Database (optional; defaults to SQLite)
# DATABASE_URL=sqlite:///instance/app.db
No default issuer email or password is provided. Deployers must supply their own credentials.

Database Initialization
By default, the application uses SQLite.

Database file: instance/app.db

ORM: SQLAlchemy

On first application startup:

The database file is created automatically if missing.

Base tables are initialized by the application.

Schema updates are handled via migration scripts.

No manual database creation is required for local development.

Database Migration
Schema updates are managed using:

powershell
Copy code
  .\.venv\Scripts\python.exe scripts/migrate_issued_credentials.py
This script is idempotent and safely:

Adds missing columns

Backfills expiry metadata

Updates authentication key and certificate tracking fields

Run this script whenever pulling new changes.

## Running the Application
Start the Flask development server from the repository root:

powershell
Copy code
.\.venv\Scripts\python.exe app.py
Access the application at:

Landing page: http://127.0.0.1:5000

Issuer dashboard: http://127.0.0.1:5000/issuer/dashboard

## Development Seed Issuer Account
For local development and evaluation, a sample issuer account can be created manually.

This allows reviewers or testers using the same dataset to log in immediately and verify issuer functionality.

This account is for development use only.
Do not use these credentials in production.

# Sample Issuer Credentials
Email: issuer@example.com

Username: ISSUER001

Password: StrongPassword123

Role: Issuer

Creating the Issuer Account
Open a Python shell from the project root:

powershell
Copy code
.\.venv\Scripts\python.exe
Run the following:

python
Copy code
from web_project import app, db
from web_project.model import User

with app.app_context():
    issuer = User(
        student_id="ISSUER001",
        first_name="John",
        last_name="Doe",
        email="issuer@example.com",
        image_path="default.png",
        section=None,
        counselor_email="counselor@example.com",
        is_issuer=True
    )
    issuer.password = "StrongPassword123"
    db.session.add(issuer)
    db.session.commit()
The issuer can now log in and access the issuer dashboard.

## Zero-Knowledge Demo Harness
scripts/zk_flow_demo.py provisions a deterministic demo credential and exercises the ZKP endpoints server-side.

powershell
Copy code
.\.venv\Scripts\python.exe scripts/zk_flow_demo.py
The script:

Creates or refreshes a demo credential

Requests a nonce from /zkp/challenge

Builds a placeholder proof commitment

Posts to /zkp/verify and prints the JSON response

Automated Attack Lab
scripts/security_attack_lab.py simulates adversarial scenarios:

powershell
Copy code
.\.venv\Scripts\python.exe scripts/security_attack_lab.py
The harness tests:

ZKP commitment tampering

Signup attempts without verification

Results are emitted as JSON and logged as security events.

## Student Credential Wallet
Each issued credential has a wallet endpoint:

bash
Copy code
/wallet/<credential_hash>
Students and verifiers can:

View certificate metadata

Launch verification flows

Scan or present QR codes

Wallet QR codes are stored under:

swift
Copy code
static/credentials/qr/
They are regenerated automatically if missing.

Issuer Analytics and Adaptive Risk
Issuance counts and grouped security events

CSV export at /issuer/security-events/export

Adaptive risk checks based on verification age, IP changes, and recent warnings

High-risk signups are blocked and logged

Real Zero-Knowledge Verification (Optional)
For Groth16-based proofs, place verifier assets under:

arduino
Copy code
web_project/static/zkp/
Configure:

powershell
Copy code
set SNARKJS_CMD=npx snarkjs
set ZKP_VKEY_PATH=C:\path\to\verification_key.json
Failures are logged as zk_engine_unavailable or zk_real_proof_invalid.

Authentication Key and Certificate Workflow
Issuer provides an authentication key during credential minting.

The key is salted and hashed before storage.

A unique certificate ID is generated per issuance.

Students receive plaintext values in the credential package.

Signup succeeds only after ZKP verification and key validation.

Troubleshooting
Missing columns: rerun the migration script.

Face recognition errors: verify system dependencies.

Credential mismatch: ensure verification was completed recently and the correct key is used.
