# SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
# Copyright (c) 2026 Parrish Lyon. All rights reserved.
"""SENTINEL WSGI export and explicit local-development launcher."""
from backend.app import app, run

__all__ = ["app"]

if __name__ == "__main__":
    run()
