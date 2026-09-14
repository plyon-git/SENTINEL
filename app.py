# SENTINEL | Parrish Lyon | PL-SENTINEL-20260914
# Copyright (c) 2026 Parrish Lyon. All rights reserved.

from backend.app import app

# Re-export for `gunicorn app:app` / `flask run` compatibility.
__all__ = ['app']
