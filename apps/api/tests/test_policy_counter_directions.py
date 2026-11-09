"""Regression: management counter must not replace forwarding upload metric."""
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

path = Path(__file__).resolve().parents[3] / "scripts" / "vpngw-policy-agent.py"
spec = importlib.util.spec_from_file_location("counter_agent", path)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def expr_match(kind, key, value, op="=="):
    left = {"meta": {"key": key}} if kind == "meta" else {"payload": {"protocol": "ip", "field": key}}
    return {"match": {"op": op, "left": left, "right": value}}


def rule(expressions):
    return {"rule": {"expr": expressions}}


class CounterDirectionsTest(unittest.TestCase):
    def test_vpn_skips_management_counter(self):
        data = {"nftables": [
            rule([expr_match("meta", "iifname", "ens18"), expr_match("payload", "saddr", "192.168.1.234"),
                  expr_match("payload", "daddr", "172.18.0.3"), {"counter": {"bytes": 0, "packets": 0}}, {"accept": None}]),
            rule([expr_match("meta", "iifname", "ens18"), expr_match("meta", "oifname", "wg0"),
                  expr_match("payload", "saddr", "192.168.1.234"),
                  {"counter": {"bytes": 100, "packets": 2}}, {"accept": None}]),
            rule([expr_match("meta", "iifname", "wg0"), expr_match("meta", "oifname", "ens18"),
                  expr_match("payload", "daddr", "192.168.1.234"),
                  {"counter": {"bytes": 400, "packets": 4}}, {"accept": None}]),
        ]}
        state = {"status": "active", "plan": {"destination": "vpn-wire", "lan": "ens18", "host": "192.168.1.234"},
                 "vpn_runtime": {"interface": "wg0"}}
        with patch.object(agent, "inspect_rules", return_value=True), patch.object(agent, "run", return_value=SimpleNamespace(stdout=json.dumps(data))):
            counters = agent.read_counters("stremio", state)
        self.assertEqual(counters["tx_bytes"], 100)
        self.assertEqual(counters["rx_bytes"], 400)

    def test_blocked_reports_rejected_only(self):
        data = {"nftables": [rule([expr_match("meta", "iifname", "ens18"),
                     expr_match("payload", "saddr", "192.168.1.249"),
                     {"counter": {"bytes": 7800, "packets": 150}}, {"drop": None}])]}
        state = {"status": "active", "plan": {"destination": "blocked", "lan": "ens18", "host": "192.168.1.249"}}
        with patch.object(agent, "inspect_rules", return_value=True), patch.object(agent, "run", return_value=SimpleNamespace(stdout=json.dumps(data))):
            result = agent.read_counters("lenovo", state)
        self.assertEqual(result, {"dropped_bytes": 7800, "dropped_packets": 150})


if __name__ == "__main__":
    unittest.main()
