# SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
# Copyright (c) 2026 Parrish Lyon. All rights reserved.
"""SENTINEL API entrypoint with local integrity enforcement and attribution."""
import logging
import os
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, request
from flask_cors import CORS

from sentinel_guard import enforce_startup, identity

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# Checks only local files, before importing application routes. It never phones home.
enforce_startup(PROJECT_ROOT)

from backend.routes import register_routes

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024
app.config["DEBUG"] = False

# Same-origin UI works without CORS. Cross-origin access must be explicitly configured.
origins = [value.strip() for value in os.environ.get("SENTINEL_CORS_ORIGINS", "").split(",") if value.strip()]
for origin in origins:
    parsed = urlsplit(origin)
    if "*" in origin or parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise RuntimeError("SENTINEL_CORS_ORIGINS must contain exact http(s) origins without paths or wildcards")
if origins:
    CORS(app, origins=origins, supports_credentials=False)

register_routes(app)


@app.get("/identity")
def ownership_identity():
    return jsonify(identity())


@app.after_request
def attribute_response(response):
    stamp = identity()
    response.headers["X-Sentinel-Owner"] = stamp["owner"]
    response.headers["X-Sentinel-Watermark"] = stamp["watermark_id"]
    response.headers["X-Sentinel-Build"] = stamp["build_id"]
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
    if response.is_json:
        response.headers["Cache-Control"] = "no-store"
        if request.path == "/upload" and 200 <= response.status_code < 300:
            payload = response.get_json(silent=True)
            if isinstance(payload, dict):
                payload["_sentinel"] = stamp
                response.set_data(app.json.dumps(payload))
    return response


def run():
    """Development server only. Production needs a WSGI server and authentication."""
    port = int(os.environ.get("PORT", "5000"))
    if not 1 <= port <= 65535:
        raise ValueError("PORT must be between 1 and 65535")
    app.run(debug=False, host=os.environ.get("SENTINEL_HOST", "127.0.0.1"), port=port)


if __name__ == "__main__":
    run()
