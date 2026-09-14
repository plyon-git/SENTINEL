# SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
# Copyright (c) 2026 Parrish Lyon. All rights reserved.
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sentinel_guard as guard


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in guard.REQUIRED:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(guard.PREFIXES.get(path.suffix, "") + "\n", encoding="utf-8")
        (self.root / "OWNERSHIP.json").write_text(json.dumps(guard.identity()), encoding="utf-8")
        (self.root / ".github/CODEOWNERS").write_text("* @plyon-git\n", encoding="utf-8")
        (self.root / guard.MANIFEST).write_text(json.dumps(guard.candidate(self.root)), encoding="utf-8")

    def test_pristine_passes(self):
        self.assertEqual(guard.verify(self.root), [])

    def test_change_detected(self):
        with (self.root / "app.py").open("a") as stream:
            stream.write("changed = True\n")
        self.assertTrue(any("SHA-256 mismatch" in e for e in guard.verify(self.root)))

    def test_removal_detected(self):
        (self.root / "app.py").unlink()
        self.assertTrue(any("missing" in e for e in guard.verify(self.root)))

    def test_unbaselined_file_detected(self):
        (self.root / "extra.py").write_text(guard.PREFIXES[".py"], encoding="utf-8")
        self.assertTrue(any("Unbaselined file" in e for e in guard.verify(self.root)))

    def test_watermark_removal_detected_even_after_hash_update(self):
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        manifest = json.loads((self.root / guard.MANIFEST).read_text())
        manifest["files"]["app.py"] = guard.sha256(self.root / "app.py")
        (self.root / guard.MANIFEST).write_text(json.dumps(manifest))
        self.assertTrue(any("watermark" in e for e in guard.verify(self.root)))

    def test_missing_manifest_fails_closed(self):
        (self.root / guard.MANIFEST).unlink()
        self.assertTrue(guard.verify(self.root))
        with patch.dict(os.environ, {"SENTINEL_INTEGRITY_MODE": "enforce"}):
            with self.assertRaises(RuntimeError):
                guard.enforce_startup(self.root)

    def test_invalid_json_fails(self):
        (self.root / guard.MANIFEST).write_text("not json")
        self.assertTrue(guard.verify(self.root))

    def test_empty_manifest_fails(self):
        value = {"schema_version": 1, **guard.identity(), "files": {}}
        (self.root / guard.MANIFEST).write_text(json.dumps(value))
        self.assertTrue(guard.verify(self.root))

    def test_path_traversal_rejected(self):
        value = {"schema_version": 1, **guard.identity(), "files": {"../outside.py": "0" * 64}}
        (self.root / guard.MANIFEST).write_text(json.dumps(value))
        self.assertIn("Unsafe path", guard.verify(self.root)[0])

    def test_invalid_digest_rejected(self):
        value = {"schema_version": 1, **guard.identity(), "files": {"app.py": "bad"}}
        (self.root / guard.MANIFEST).write_text(json.dumps(value))
        self.assertIn("Invalid SHA-256", guard.verify(self.root)[0])

    def test_identity_change_rejected(self):
        value = json.loads((self.root / guard.MANIFEST).read_text())
        value["owner"] = "Someone else"
        (self.root / guard.MANIFEST).write_text(json.dumps(value))
        self.assertIn("identity mismatch", guard.verify(self.root)[0])

    def test_owner_file_change_rejected(self):
        (self.root / "OWNERSHIP.json").write_text('{}')
        self.assertTrue(any("OWNERSHIP.json" in e for e in guard.verify(self.root)))

    def test_codeowners_removal_rejected(self):
        (self.root / ".github/CODEOWNERS").write_text("# removed\n")
        self.assertTrue(any("CODEOWNERS" in e for e in guard.verify(self.root)))

    def test_symlink_rejected(self):
        (self.root / "link.py").symlink_to(self.root / "app.py")
        self.assertTrue(guard.verify(self.root))

    def test_local_data_and_cache_ignored(self):
        (self.root / "uploads").mkdir()
        (self.root / "uploads/private.csv").write_text("private data")
        (self.root / "__pycache__").mkdir()
        (self.root / "__pycache__/app.pyc").write_bytes(b"cache")
        (self.root / ".env").write_text("LOCAL_ONLY=example")
        self.assertEqual(guard.verify(self.root), [])

    def test_explicit_development_bypass(self):
        (self.root / guard.MANIFEST).unlink()
        with patch.dict(os.environ, {"SENTINEL_INTEGRITY_MODE": "off"}):
            guard.enforce_startup(self.root)

    def test_invalid_mode_rejected(self):
        with patch.dict(os.environ, {"SENTINEL_INTEGRITY_MODE": "typo"}):
            with self.assertRaises(RuntimeError):
                guard.enforce_startup(self.root)

    def test_check_does_not_rewrite_baseline(self):
        before = (self.root / guard.MANIFEST).read_bytes()
        (self.root / "app.py").write_text("modified")
        guard.verify(self.root)
        self.assertEqual(before, (self.root / guard.MANIFEST).read_bytes())

    def test_baseline_requires_explicit_approval(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                guard.main(["baseline", "--root", str(self.root)])

    def test_secret_pattern_and_redacted_output(self):
        token = "gh" + "p_" + "A" * 36
        (self.root / "sample.txt").write_text(token)
        errors = guard.scan_secrets(self.root)
        self.assertTrue(any("github-token" in e for e in errors))
        self.assertFalse(any(token in e for e in errors))

    def test_clean_secret_scan(self):
        self.assertEqual(guard.scan_secrets(self.root), [])


if __name__ == "__main__":
    unittest.main()
