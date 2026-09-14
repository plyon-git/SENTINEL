# SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
# Copyright (c) 2026 Parrish Lyon. All rights reserved.
import io
import os
import unittest
from unittest.mock import patch

from sentinel_guard import identity


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Integrity failure behavior is tested independently with temporary fixtures.
        # This permits smoke tests during the initial, pre-baseline migration commit.
        with patch.dict(os.environ, {"SENTINEL_INTEGRITY_MODE": "off", "SENTINEL_CORS_ORIGINS": ""}):
            from backend.app import app
        cls.app = app
        cls.app.config["TESTING"] = True

    def setUp(self):
        self.client = self.app.test_client()

    def test_health_and_attribution(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "healthy")
        self.assertEqual(response.headers["X-Sentinel-Owner"], "Parrish Lyon")
        self.assertEqual(response.headers["X-Sentinel-Watermark"], identity()["watermark_id"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_identity_endpoint(self):
        self.assertEqual(self.client.get("/identity").json, identity())

    def test_debug_disabled(self):
        self.assertFalse(self.app.debug)

    def test_default_cors_not_wildcard(self):
        response = self.client.get("/health", headers={"Origin": "https://untrusted.example"})
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)

    def test_index_contains_internal_attribution(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PARRISH-LYON-SENTINEL-2026", response.data)
        self.assertIn(b"Parrish Lyon", response.data)
        response.close()

    def test_upload_requires_file(self):
        self.assertEqual(self.client.post("/upload").status_code, 400)

    def test_upload_rejects_non_csv(self):
        response = self.client.post("/upload", data={"file": (io.BytesIO(b"example"), "example.txt")})
        self.assertEqual(response.status_code, 400)

    def test_csv_analysis_smoke(self):
        rows = ["timestamp,user_id,order_value,ip_address,payment_method,email,country,order_id"]
        for index in range(6):
            rows.append(f"2026-01-01 12:0{index}:00,user_{index},100,8.8.8.8,synthetic_card_{index},demo{index}@example.invalid,US,order_{index}")
        payload = ("\n".join(rows) + "\n").encode()
        response = self.client.post("/upload", data={"file": (io.BytesIO(payload), "synthetic.csv")})
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json["total_rows"], 6)
        self.assertEqual(sum(response.json["risk_counts"].values()), 6)
        self.assertEqual(response.json["_sentinel"], identity())


if __name__ == "__main__":
    unittest.main()
