"""Regression: policy routing must not send the WebAdmin Docker proxy into WireGuard."""
import importlib.util
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).parents[1] / "scripts" / "vpngw_management_access.py"
SPEC = importlib.util.spec_from_file_location("vpngw_management_access_test", SCRIPT)
mgmt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mgmt)
PROXY = {"gateway": "192.168.1.231", "proxy": "172.18.0.2", "port": 443}


def test_exception_is_bound_to_mac_source_proxy_and_https():
    with mock.patch.object(mgmt, "target", return_value=PROXY):
        rule = mgmt.match("192.168.1.249", "7c:b5:66:9e:f7:be", "ens18")
    assert 'iifname "ens18"' in rule
    assert "ether saddr 7c:b5:66:9e:f7:be" in rule
    assert "ip saddr 192.168.1.249" in rule
    assert "ip daddr 172.18.0.2 tcp dport 443" in rule
    assert "1.1.1.1" not in rule


def test_management_exception_rejects_invalid_mac():
    with mock.patch.object(mgmt, "target", return_value=PROXY):
        try:
            mgmt.match("192.168.1.249", "00:invalid", "ens18")
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid MAC must not be accepted")


def test_ensure_adds_specific_rule_before_source_based_vpn_rule():
    calls = []
    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if args[:4] == ["/usr/sbin/ip", "-4", "rule", "show"]:
            return mock.Mock(returncode=0, stdout="13475: from 192.168.1.249 iif ens18 lookup 23475\n")
        if args[:4] == ["/usr/sbin/ip", "-4", "route", "get"]:
            return mock.Mock(returncode=0, stdout="172.18.0.2 dev br-test\n")
        return mock.Mock(returncode=0, stdout="")
    with mock.patch.object(mgmt, "target", return_value=PROXY), mock.patch.object(
        mgmt.subprocess, "run", side_effect=fake_run
    ):
        mgmt.ensure("lenovo", "192.168.1.249", "7c:b5:66:9e:f7:be", "ens18")
    assert any(args[:5] == ["/usr/sbin/ip", "-4", "rule", "add", "pref"]
               and "9000" in args and "172.18.0.2/32" in args
               for args, _ in calls)
    scripts = [kw["input"] for args, kw in calls if args[-2:] == ["-f", "-"]]
    assert scripts and all("tcp dport 443" in s for s in scripts)
    assert all("7c:b5:66:9e:f7:be" in s for s in scripts)
