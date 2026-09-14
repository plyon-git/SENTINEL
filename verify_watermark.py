#!/usr/bin/env python3
# SENTINEL | Parrish Lyon | PL-SENTINEL-20260914
# Copyright (c) 2026 Parrish Lyon. All rights reserved.
"""Check the six uploaded files against the committed ownership manifest.

This is change detection, not a signature or protection against an editor who
can change both the files and the manifest. No files are modified.
"""
from pathlib import Path
import hashlib
import json
import sys

EXPECTED = frozenset({
    "app.py", "generate_orders_large.py", "ledgewell_file_map.txt",
    "README.md", "requirements.txt", "vercel.json",
})


def main() -> int:
    root = Path(__file__).resolve().parent
    try:
        manifest = json.loads((root / "SENTINEL_WATERMARK.json").read_text(encoding="utf-8"))
        entries = manifest["files"]
        if manifest.get("owner") != "Parrish Lyon":
            raise ValueError("Unexpected ownership label")
        if manifest.get("watermark_id") != "PL-SENTINEL-20260914":
            raise ValueError("Unexpected watermark identifier")
        if set(entries) != EXPECTED:
            raise ValueError("Manifest must cover exactly the six uploaded files")
        failed = []
        for name in sorted(EXPECTED):
            path = root / name
            if path.is_symlink() or not path.is_file():
                failed.append(name + ": missing, not a file, or a symlink")
                continue
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != entries[name]["sha256"]:
                failed.append(name + ": checksum mismatch")
        if failed:
            print("Watermark integrity check FAILED:", file=sys.stderr)
            print("\n".join(failed), file=sys.stderr)
            return 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Watermark verification failed: {exc}", file=sys.stderr)
        return 1
    print("PASS: all six files match Parrish Lyon's committed watermark manifest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
