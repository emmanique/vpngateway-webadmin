import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from fastapi import HTTPException
import system_maintenance as maintenance


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "admin.sqlite3")
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TABLE connections(id TEXT PRIMARY KEY,payload TEXT NOT NULL)")
            db.execute("CREATE TABLE policies(id TEXT PRIMARY KEY,payload TEXT NOT NULL)")
            db.execute("INSERT INTO connections VALUES(?,?)", ("vpn-demo", json.dumps({"protocol": "wireguard"})))
    def tearDown(self):
        self.tmp.cleanup()
    def test_roundtrip_draft_configuration(self):
        snapshot = maintenance.snapshot(self.db)
        self.assertFalse(snapshot["includes_vpn_secrets"])
        data = maintenance.validate(snapshot)
        maintenance.safe_to_change(self.db)
        maintenance.apply(self.db, {key: [] for key in maintenance.TABLES})
        maintenance.apply(self.db, data)
        self.assertEqual(maintenance.snapshot(self.db)["data"]["connections"], data["connections"])
    def test_active_policy_blocks_mutations(self):
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO policies VALUES(?,?)", ("host-a", json.dumps({"status": "active"})))
        with self.assertRaises(HTTPException) as caught:
            maintenance.safe_to_change(self.db)
        self.assertEqual(caught.exception.status_code, 409)
        with self.assertRaises(HTTPException):
            maintenance.validate(maintenance.snapshot(self.db))
    def test_invalid_and_oversized_payload(self):
        with self.assertRaises(HTTPException):
            maintenance.validate({"format": "other", "schema": 1, "data": {}})
        invalid = maintenance.snapshot(self.db)
        invalid["data"]["connections"][0]["payload"] = "not-json"
        with self.assertRaises(HTTPException):
            maintenance.validate(invalid)


if __name__ == "__main__":
    unittest.main()
