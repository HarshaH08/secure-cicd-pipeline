"""
Minimal Flask app demonstrating secure-by-default patterns.
Security controls baked in (not bolted on):
  - No hardcoded secrets (env vars only)
  - Input validation
  - Security headers via Flask-Talisman
  - Structured logging (no sensitive data in logs)
"""

import logging
import os
import re
from http import HTTPStatus

from flask import Flask, jsonify, request
from flask_talisman import Talisman

# ─────────────────────────────────────────────
# Structured logging — never log request bodies,
# tokens, passwords, or PII
# ─────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ─────────────────────────────────────────────
# Security headers via Flask-Talisman
# Maps to: Content-Security-Policy, HSTS,
# X-Content-Type-Options, X-Frame-Options
# ─────────────────────────────────────────────
csp = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": "'self'",
    "img-src": "'self' data:",
    "object-src": "'none'",
}

Talisman(
    app,
    content_security_policy=csp,
    force_https=os.getenv("FLASK_ENV") == "production",
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    frame_options="DENY",
    referrer_policy="strict-origin-when-cross-origin",
)

# ─────────────────────────────────────────────
# Secrets from environment — NEVER hardcoded
# ─────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set.")
app.secret_key = SECRET_KEY


# ─────────────────────────────────────────────
# Input validation helper
# ─────────────────────────────────────────────
def validate_username(username: str) -> bool:
    """Allow only alphanumeric usernames (3–32 chars)."""
    return bool(re.fullmatch(r"[a-zA-Z0-9_]{3,32}", username))


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.route("/health")
def health():
    """Health check — no auth required, no sensitive data returned."""
    return jsonify({"status": "ok"}), HTTPStatus.OK


@app.route("/api/user/<username>")
def get_user(username: str):
    """
    Return user info. Demonstrates:
      - Input validation before processing
      - Generic error messages (no info leakage)
      - Structured log (no PII)
    """
    if not validate_username(username):
        logger.warning("Invalid username format in request")
        return (
            jsonify({"error": "Invalid username format."}),
            HTTPStatus.BAD_REQUEST,
        )

    logger.info("User lookup request received", extra={"username_len": len(username)})

    # Simulate a user lookup (replace with real DB query)
    return jsonify({"username": username, "active": True}), HTTPStatus.OK


@app.errorhandler(404)
def not_found(e):
    """Generic 404 — no stack traces in responses."""
    return jsonify({"error": "Not found."}), HTTPStatus.NOT_FOUND


@app.errorhandler(500)
def internal_error(e):
    """Generic 500 — never expose internal error details to clients."""
    logger.exception("Internal server error")
    return jsonify({"error": "Internal server error."}), HTTPStatus.INTERNAL_SERVER_ERROR


if __name__ == "__main__":
    # In production, use gunicorn — never flask dev server
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8080")),
        debug=False,
    )
