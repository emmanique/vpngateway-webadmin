"""Backup/restore QA with synthetic profiles, and fail-closed reactivation.

No host files, containers, or runtime VPN credentials are read or modified.
"""
import base64
import importlib.util
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("qa_maintenance",ROOT/"apps/api/system_maintenance.py")
maintenance=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(maintenance)

DUMMY_WG=b"[Interface]\nPrivateKey = DUMMY_REPLACE_WITH_VALID_32_BYTES\n[Peer]\nPublicKey = DUMMY_REPLACE_WITH_VALID_32_BYTES\nAllowedIPs = 0.0.0.0/0\n"

class DnsBackupRestoreTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix="qa-dns-backup-")
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.db=self.root/"source.sqlite3"
        self.target=self.root/"restored.sqlite3"
        self.profile=self.root/"wireguard"
        self.profile.mkdir()
        self.patch=patch.object(maintenance,"PROFILE_ROOT",self.profile)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        with sqlite3.connect(self.db) as db:
            for table in maintenance.TABLES:
                db.execute(f"CREATE TABLE {table} (id {'INTEGER' if table.endswith('_config') else 'TEXT'} PRIMARY KEY,payload TEXT NOT NULL)")
            db.execute("INSERT INTO connections VALUES(?,?)",("vpn-qa",json.dumps(
                {"protocol":"wireguard","enabled":True,"name":"Synthetic QA"})))
            db.execute("INSERT INTO policies VALUES(?,?)",("client-qa",json.dumps(
                {"host":"192.0.2.42","destination":"vpn-qa","status":"active",
                 "registered_mac":"02:00:00:00:00:42"})))
            db.execute("INSERT INTO network_config VALUES(?,?)",(1,json.dumps(
                {"applied":True,"mode":"routed"})))
            db.execute("INSERT INTO dns_config VALUES(?,?)",(1,json.dumps(
                {"upstream_ipv4":["1.1.1.1"]})))
        (self.profile/"vpn-qa.conf").write_bytes(DUMMY_WG)

    def test_encrypted_backup_restores_configuration_but_never_activates_policy(self):
        password=secrets.token_urlsafe(24)
        backup=maintenance.encrypted_snapshot(self.db,password)
        self.assertEqual(backup["schema"],2)
        self.assertNotIn("192.0.2.42",json.dumps(backup))
        self.assertNotIn("PrivateKey",json.dumps(backup))
        restored,profiles,openvpn=maintenance.decrypt_backup(backup,password)
        self.assertEqual(profiles["vpn-qa"],DUMMY_WG)
        self.assertEqual(openvpn,{})
        self.assertEqual(json.loads(restored["policies"][0]["payload"])["status"],"draft")
        self.assertFalse(json.loads(restored["network_config"][0]["payload"])["applied"])
        self.assertFalse(json.loads(restored["connections"][0]["payload"])["enabled"])
        maintenance.restore_wireguard(self.target,restored,profiles)
        with sqlite3.connect(self.target) as db:
            state=json.loads(db.execute("SELECT payload FROM policies WHERE id='client-qa'").fetchone()[0])
            net=json.loads(db.execute("SELECT payload FROM network_config WHERE id=1").fetchone()[0])
        self.assertEqual(state["destination"],"vpn-qa")
        self.assertEqual(state["status"],"draft")
        self.assertFalse(net["applied"])
        self.assertEqual((self.profile/"vpn-qa.conf").read_bytes(),DUMMY_WG)
        self.assertEqual((self.profile/"vpn-qa.conf").stat().st_mode&0o777,0o600)

    def test_tampered_backup_rejected_before_restore(self):
        backup=maintenance.encrypted_snapshot(self.db,"TemporaryPasswordOfQaOnly!")
        data=base64.b64decode(backup["ciphertext"])
        backup["ciphertext"]=base64.b64encode(data[:-1]+bytes([data[-1]^1])).decode()
        with self.assertRaises(Exception):
            maintenance.decrypt_backup(backup,"TemporaryPasswordOfQaOnly!")

    def test_wrong_password_rejected(self):
        backup=maintenance.encrypted_snapshot(self.db,"TemporaryPasswordOfQaOnly!")
        with self.assertRaises(Exception):
            maintenance.decrypt_backup(backup,"NotSamePasswordInQa!")

if __name__=="__main__":
    unittest.main()
