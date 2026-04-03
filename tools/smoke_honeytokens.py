#!/usr/bin/env python3
"""Smoke-test the decoy webapp honeytoken paths.

This script uses Flask's test client to exercise:
- API key generation + use ("phones home" via /api/v1/profile)
- Password reset token generation + click (/webapp/reset/<token>)
- Tracking pixel hit (/honey/<token>.png)

It prints the latest rows from the `attacks` table so you can confirm
that events are persisted and will show up on the dashboard.

Usage:
  python3 tools/smoke_honeytokens.py
"""

from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path

# Ensure repo root is importable when running as `python3 tools/...`.
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app import app


def _find_first(text: str, pattern: str) -> str | None:
    m = re.search(pattern, text)
    return m.group(1) if m else None


def main() -> None:
    client = app.test_client()

    # 0) Fetch home to extract an issued tracking pixel token
    r = client.get("/webapp")
    assert r.status_code == 200
    html = r.data.decode("utf-8", errors="ignore")
    pixel_token = _find_first(html, r"/honey/([A-Za-z0-9_\-]{16,})\.png")
    if not pixel_token:
        raise RuntimeError("Could not extract pixel token from /webapp response")

    # 1) API key generation + use
    r = client.post("/webapp/api-keys")
    assert r.status_code == 200
    html = r.data.decode("utf-8", errors="ignore")

    api_key = _find_first(html, r"(nhp_live_[A-Za-z0-9_\-]{10,})")
    if not api_key:
        raise RuntimeError("Could not extract API key from /webapp/api-keys response")

    r = client.get("/api/v1/profile", headers={"X-API-Key": api_key})
    assert r.status_code == 200

    # 2) Password reset token generation + click
    r = client.post("/webapp/password-reset", data={"email": "admin@acme.internal"})
    assert r.status_code == 200
    html = r.data.decode("utf-8", errors="ignore")

    reset_token = _find_first(html, r"/webapp/reset/([A-Za-z0-9_\-]{16,})")
    if not reset_token:
        raise RuntimeError("Could not extract reset token from /webapp/password-reset response")

    r = client.get(f"/webapp/reset/{reset_token}")
    assert r.status_code == 200

    # 3) Tracking pixel hit
    r = client.get(f"/honey/{pixel_token}.png")
    assert r.status_code == 200

    # 4) Verify persistence
    conn = sqlite3.connect("honeypot.db")
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, service, category, payload FROM attacks ORDER BY id DESC LIMIT 15"
    ).fetchall()
    conn.close()

    print("API key:", api_key)
    print("Reset token:", reset_token)
    print("Pixel token:", pixel_token)
    print("\nLatest attacks:")
    for row in rows:
        print(dict(row))


if __name__ == "__main__":
    main()
