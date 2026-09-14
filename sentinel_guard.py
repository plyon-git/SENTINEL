# SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
# Copyright (c) 2026 Parrish Lyon. All rights reserved.
"""Local attribution and integrity checks. No network access or destructive actions."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

OWNER = "Parrish Lyon"
MARKER = "PARRISH-LYON-SENTINEL-2026"
SOURCE_COMMIT = "33b0697a47ecdaf2cc152f39c1d37e50e87f2917"
BUILD_ID = "PL-SENTINEL-20260914-33b0697a"
MANIFEST = "integrity.sha256.json"
PREFIXES = {
    ".py": "# SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026\n# Copyright (c) 2026 Parrish Lyon. All rights reserved.\n",
    ".js": "// SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026\n// Copyright (c) 2026 Parrish Lyon. All rights reserved.\n",
    ".css": "/* SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026\n * Copyright (c) 2026 Parrish Lyon. All rights reserved. */\n",
    ".html": "<!-- SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026\n     Copyright (c) 2026 Parrish Lyon. All rights reserved. -->\n",
}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "uploads", "data", "exports", "dist", "build", ".vercel"}
SKIP_SUFFIXES = {".pyc", ".pyo", ".csv", ".sqlite", ".db", ".log"}
REQUIRED = {"app.py", "backend/app.py", "frontend/index.html", "sentinel_guard.py", "OWNERSHIP.json", "NOTICE", ".github/CODEOWNERS"}


def identity() -> dict[str, str]:
    return {"project": "SENTINEL", "owner": OWNER, "watermark_id": MARKER, "build_id": BUILD_ID, "source_commit": SOURCE_COMMIT}


def project_files(root: Path) -> dict[str, Path]:
    """Include source and support files; exclude local data, secrets, and build caches."""
    root = root.resolve()
    result: dict[str, Path] = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError("Symlinked project directory is not allowed")
        for name in sorted(names):
            path = Path(directory) / name
            rel = path.relative_to(root).as_posix()
            if rel == MANIFEST or name == ".DS_Store" or path.suffix in SKIP_SUFFIXES:
                continue
            if name.startswith(".env") and name != ".env.example":
                continue
            if path.is_symlink():
                raise ValueError(f"Symlinked project file is not allowed: {rel}")
            result[rel] = path
    return dict(sorted(result.items()))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def attribution_errors(root: Path, files: dict[str, Path]) -> list[str]:
    errors = [f"Required file missing: {name}" for name in sorted(REQUIRED - files.keys())]
    for name, path in files.items():
        prefix = PREFIXES.get(path.suffix)
        if prefix and not path.read_bytes().startswith(prefix.encode("utf-8")):
            errors.append(f"Ownership watermark missing or changed: {name}")
    try:
        owner = json.loads((root / "OWNERSHIP.json").read_text(encoding="utf-8"))
        if any(owner.get(key) != value for key, value in identity().items()):
            errors.append("OWNERSHIP.json identity does not match this distribution")
    except (OSError, ValueError, AttributeError):
        errors.append("OWNERSHIP.json is missing or invalid")
    try:
        rules = (root / ".github/CODEOWNERS").read_text(encoding="utf-8").splitlines()
        if not any(line.split() == ["*", "@plyon-git"] for line in rules):
            errors.append("CODEOWNERS must contain the rule: * @plyon-git")
    except OSError:
        errors.append("CODEOWNERS is missing")
    return errors


def candidate(root: Path) -> dict:
    files = project_files(root)
    errors = attribution_errors(root, files)
    if errors:
        raise ValueError("\n".join(errors))
    return {"schema_version": 1, **identity(), "files": {name: sha256(path) for name, path in files.items()}}


def verify(root: Path) -> list[str]:
    """Return failures without changing any file. The manifest is never auto-repaired."""
    root = root.resolve()
    try:
        document = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("schema_version") != 1:
            return ["Unsupported or invalid integrity manifest"]
        if any(document.get(key) != value for key, value in identity().items()):
            return ["Integrity manifest identity mismatch"]
        expected = document.get("files")
        if not isinstance(expected, dict) or not expected:
            return ["Integrity manifest must contain a nonempty file map"]
        for name, digest in expected.items():
            if not isinstance(name, str) or not name or "\\" in name or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts or str(PurePosixPath(name)) != name or name == MANIFEST:
                return ["Unsafe path in integrity manifest"]
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                return ["Invalid SHA-256 in integrity manifest"]
        actual = project_files(root)
        errors = attribution_errors(root, actual)
        errors.extend(f"File missing: {name}" for name in sorted(expected.keys() - actual.keys()))
        errors.extend(f"Unbaselined file: {name}" for name in sorted(actual.keys() - expected.keys()))
        errors.extend(f"SHA-256 mismatch: {name}" for name in sorted(actual.keys() & expected.keys()) if sha256(actual[name]) != expected[name])
        return errors
    except (OSError, ValueError, TypeError) as exc:
        return [f"Cannot verify integrity: {type(exc).__name__}"]


def enforce_startup(root: Path) -> None:
    mode = os.environ.get("SENTINEL_INTEGRITY_MODE", "enforce")
    if mode == "off":
        logging.getLogger("sentinel").warning("SENTINEL integrity enforcement is OFF. Development only.")
        return
    if mode != "enforce":
        raise RuntimeError("SENTINEL_INTEGRITY_MODE must be enforce or off")
    errors = verify(root)
    if errors:
        raise RuntimeError("SENTINEL integrity check failed. Review changes before rebaselining:\n" + "\n".join(errors[:20]))


SECRET_RULES = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "stripe-live-key": re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
}


def scan_secrets(root: Path) -> list[str]:
    """A focused tracked-file check, not a complete secret or vulnerability audit."""
    root = root.resolve()
    if (root / ".git").exists():
        output = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True).stdout
        names = [name.decode("utf-8") for name in output.split(b"\0") if name]
    else:
        names = list(project_files(root))
    errors: list[str] = []
    for name in names:
        path = root / name
        if not path.is_file() or path.is_symlink():
            continue
        if (path.name.startswith(".env") and path.name != ".env.example") or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".pyc", ".csv", ".sqlite", ".db"}:
            errors.append(f"Sensitive/generated file is tracked: {name}")
            continue
        text = path.read_bytes().decode("utf-8", errors="replace")
        for rule, regex in SECRET_RULES.items():
            for match in regex.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                errors.append(f"Possible {rule}: {name}:{line} (value withheld)")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "candidate", "baseline", "secrets"])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--approve", action="store_true", help="Explicitly approve writing a new local baseline after reviewing the diff")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if args.command in {"candidate", "baseline"}:
            if args.command == "baseline" and not args.approve:
                parser.error("baseline requires --approve; inspect and approve all changes first")
            document = json.dumps(candidate(root), indent=2, sort_keys=True) + "\n"
            if args.command == "candidate":
                print(document, end="")
            else:
                (root / MANIFEST).write_text(document, encoding="utf-8", newline="\n")
                print(f"Wrote {MANIFEST}. Review and commit the manifest with the approved changes.")
            return 0
        errors = verify(root) if args.command == "check" else scan_secrets(root)
        for error in errors:
            print(error, file=sys.stderr)
        if errors:
            return 1
        print("SENTINEL integrity verified." if args.command == "check" else "Focused tracked-file secret scan passed.")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
