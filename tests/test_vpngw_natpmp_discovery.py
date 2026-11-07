"""NAT-PMP regression tests with a fake kernel route table; no network access."""
import importlib.util
from pathlib import Path
import json
import types
import unittest
import tempfile
import hashlib
import os
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "vpngw-natpmp-discovery.py"
spec = importlib.util.spec_from_file_location("vpngw_natpmp_discovery", SOURCE)
natpmp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(natpmp)


class FakeRunner:
    def __init__(self, correct_tunnel=True, map_tcp=True, map_udp=True, allow_scoped_route=False, tunnel="wgsecure"):
        self.calls = []
        self.correct_tunnel = correct_tunnel
        self.tunnel = tunnel
        self.map_tcp = map_tcp
        self.map_udp = map_udp
        self.allow_scoped_route = allow_scoped_route
        self.scoped = False

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if args[:5] == ["/usr/sbin/ip", "-j", "-4", "route", "get"]:
            return types.SimpleNamespace(returncode=0, stdout=json.dumps([
                {"dev": self.tunnel if self.correct_tunnel or self.scoped else "ens18"}]))
        if args[:5] == ["/usr/sbin/ip", "-j", "-4", "route", "show"]:
            if "exact" in args:
                return types.SimpleNamespace(returncode=0, stdout="[]")
            return types.SimpleNamespace(returncode=0, stdout=json.dumps([
                {"gateway": "10.2.0.1"}]))
        if args[:4] == ["/usr/sbin/ip", "-4", "route", "add"]:
            self.scoped = self.allow_scoped_route
            return types.SimpleNamespace(returncode=0 if self.scoped else 1, stdout="")
        if args[:4] == ["/usr/sbin/ip", "-4", "route", "del"]:
            self.scoped = False
            return types.SimpleNamespace(returncode=0, stdout="")
        if args[:5] == ["/usr/sbin/ip", "-j", "-4", "address", "show"]:
            return types.SimpleNamespace(returncode=0, stdout=json.dumps([
                {"addr_info": [{"family": "inet", "local": "10.2.0.2", "prefixlen": 32}]}]))
        if args[0] == "/usr/bin/dpkg-query":
            return types.SimpleNamespace(returncode=0, stdout="20230423-1")
        if args[0] == "/usr/bin/natpmpc":
            proton = args[-2:] == ["-g", "10.2.0.1"]
            protocol = args[4] if proton else args[-2]
            if (protocol == "tcp" and not self.map_tcp) or (protocol == "udp" and not self.map_udp):
                return types.SimpleNamespace(returncode=1, stdout="NAT-PMP refused")
            port = "36131" if protocol == "udp" else "36132"
            lifetime = args[5] if proton else args[-1]
            local = "0" if proton else "6881"
            return types.SimpleNamespace(returncode=0,
                stdout=f"Mapped public port {port} protocol {protocol.upper()} to local port {local} lifetime {lifetime}")
        raise AssertionError(args)


@patch.object(natpmp, "PRIVATE_PROTON_NATPMP", Path("/nonexistent-vpngw-natpmpc-tests"))
class NATPMPTests(unittest.TestCase):
    def test_isolated_natpmp_binary_requires_exact_hash_and_version(self):
        if os.geteuid() != 0:
            self.skipTest("Root-owned isolated binary required")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vpngw-natpmpc"
            path.write_bytes(b"pretend new binary")
            (Path(str(path) + ".version")).write_text("20230423\n")
            signature = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest = Path(str(path) + ".sha256")
            manifest.write_text(signature + "  vpngw-natpmpc\n")
            old_package = FakeRunner()
            def verified_runner(args, **kwargs):
                if args[0] == "/usr/bin/sha256sum":
                    valid = manifest.read_text().strip() == hashlib.sha256(path.read_bytes()).hexdigest() + "  vpngw-natpmpc"
                    return types.SimpleNamespace(returncode=0 if valid else 1, stdout="verified" if valid else "mismatch")
                if args[0] == "/usr/bin/dpkg-query":
                    return types.SimpleNamespace(returncode=0, stdout="20150609-7.1build2")
                return old_package(args, **kwargs)
            self.assertEqual(
                natpmp.proton_natpmp_executable(verified_runner, private_path=path),
                str(path))
            manifest.write_text("0"*64 + "  vpngw-natpmpc\n")
            self.assertIsNone(natpmp.proton_natpmp_executable(verified_runner, private_path=path))
            manifest.write_text(signature + "  vpngw-natpmpc\n")
            (Path(str(path) + ".version")).write_text("20150609\n")
            self.assertIsNone(natpmp.proton_natpmp_executable(verified_runner, private_path=path))

    def test_old_proton_natpmp_binary_refuses_lease_for_both_tunnels(self):
        for iface in ("wgsecure", "tun9"):
            base = FakeRunner(tunnel=iface)
            def old_binary(args, **kwargs):
                if args[0] == "/usr/bin/dpkg-query":
                    return types.SimpleNamespace(returncode=0, stdout="20150609-7.1build2")
                return base(args, **kwargs)
            result = natpmp.discover("10.2.0.1", iface, old_binary, provider="proton")
            self.assertEqual(result["status"], "proton_natpmpc_version_unsupported")
            self.assertEqual(result["mappings"], [])
            self.assertFalse(any(args[0] == "/usr/bin/natpmpc" for args in base.calls))

    def test_proton_natpmp_package_versions(self):
        for version, expected in (("20150609-7.1build2", False),
                                   ("20230423-1", True),
                                   ("20230423+dfsg-2", True),
                                   ("20240423-1", True),
                                   ("invalid", False)):
            def mock(args, **kwargs):
                return types.SimpleNamespace(returncode=0, stdout=version)
            self.assertEqual(natpmp.proton_binary_compatible(mock), expected, version)

    def test_udp_mapping_only(self):
        runner = FakeRunner(map_tcp=False)
        observed = natpmp.discover("10.2.0.1", "wgsecure", runner)
        self.assertEqual(observed["status"], "mapped")
        self.assertEqual([p["protocol"] for p in observed["mappings"]], ["udp"])
        self.assertEqual(observed["mappings"][0]["external_port"], 36131)

    def test_proton_natpmp_wireguard_and_openvpn_use_same_command(self):
        for interface in ("wgsecure", "tun9"):
            with self.subTest(interface=interface):
                runner = FakeRunner(tunnel=interface)
                result = natpmp.discover("10.2.0.1", interface, runner, provider="proton")
                self.assertEqual(result["status"], "mapped")
                self.assertEqual({v["protocol"] for v in result["mappings"]}, {"tcp", "udp"})
                calls = [x for x in runner.calls if x[0] == "/usr/bin/natpmpc"]
                self.assertEqual(calls[0], ["/usr/bin/natpmpc","-a","1","0","tcp","60","-g","10.2.0.1"])
                self.assertEqual(calls[1], ["/usr/bin/natpmpc","-a","1","0","udp","60","-g","10.2.0.1"])
                before = len([x for x in runner.calls if x[0] == "/usr/bin/natpmpc"])
                lease = natpmp.revoke("10.2.0.1", interface, {"udp":36131}, runner, provider="proton")
                self.assertEqual(lease["revoked"], [])
                self.assertTrue(lease["expiry_only"])
                self.assertEqual(lease["lease_remaining_max_seconds"], 60)
                self.assertEqual(len([x for x in runner.calls if x[0] == "/usr/bin/natpmpc"]), before)

    def test_proton_mapping_requires_local_zero_and_documented_gateway(self):
        value="Mapped public port 36131 protocol UDP to local port 0 lifetime 60"
        self.assertEqual(natpmp.parse_mapping(value, "udp", provider="proton")["external_port"], 36131)
        self.assertIsNone(natpmp.parse_mapping(value, "udp", provider="generic"))
        self.assertEqual(natpmp.discover("10.3.0.1", "wgsecure", FakeRunner(),
                                         provider="proton")["status"], "proton_gateway_mismatch")

    def test_proton_renewal_reuses_documented_request_not_allocated_port(self):
        runner=FakeRunner()
        natpmp.discover("10.2.0.1","wgsecure",runner,
                        preferred={"udp":36131,"tcp":36132},provider="proton")
        commands=[x for x in runner.calls if x[0]=="/usr/bin/natpmpc"]
        self.assertEqual([x[2] for x in commands],["1","1"])
        self.assertEqual([x[3] for x in commands],["0","0"])
        self.assertEqual([x[5] for x in commands],["60","60"])

    def test_no_egress_through_physical_wan(self):
        runner = FakeRunner(correct_tunnel=False)
        self.assertIsNone(natpmp.candidate_gateway("wgsecure", runner))
        self.assertEqual(natpmp.discover("10.2.0.1", "wgsecure", runner)["status"],
                         "vpn_gateway_unverified")
        self.assertFalse(any(x[0] == "/usr/bin/natpmpc" for x in runner.calls))

    def test_candidate_from_private_tunnel_address(self):
        self.assertEqual(natpmp.candidate_from_tunnel_address("wgsecure", FakeRunner()),
                         "10.2.0.1")

    def test_ephemeral_route_never_leaks_and_is_removed(self):
        runner = FakeRunner(correct_tunnel=False, allow_scoped_route=True)
        with tempfile.TemporaryDirectory() as directory:
            previous = natpmp.TEMP_ROUTE_MARKER
            natpmp.TEMP_ROUTE_MARKER = Path(directory) / "temporary-route.json"
            try:
                result = natpmp.discover("10.2.0.1", "wgsecure", runner)
                self.assertEqual(result["status"], "mapped")
                self.assertFalse(runner.scoped)
                self.assertFalse(natpmp.TEMP_ROUTE_MARKER.exists())
                ops = [x for x in runner.calls if x[:4] in (
                    ["/usr/sbin/ip", "-4", "route", "add"],
                    ["/usr/sbin/ip", "-4", "route", "del"])]
                self.assertEqual(len(ops), 2)
            finally:
                natpmp.TEMP_ROUTE_MARKER = previous

    def test_failed_route_cleanup_keeps_recovery_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "route.json"
            marker.write_text(json.dumps({"gateway": "10.2.0.1", "interface": "wgsecure"}))
            def failing_runner(args, **kwargs):
                if "show" in args:
                    return types.SimpleNamespace(returncode=0, stdout=json.dumps([
                        {"dst":"10.2.0.1/32","dev":"wgsecure","protocol":"186"}]))
                return types.SimpleNamespace(returncode=1, stdout="")
            self.assertFalse(natpmp.cleanup_stale_route(failing_runner, marker))
            self.assertTrue(marker.exists())
            def success_runner(args, **kwargs):
                if "show" in args:
                    return types.SimpleNamespace(returncode=0, stdout=json.dumps([
                        {"dst":"10.2.0.1/32","dev":"wgsecure","protocol":"186"}]))
                return types.SimpleNamespace(returncode=0, stdout="")
            self.assertTrue(natpmp.cleanup_stale_route(success_runner, marker))
            self.assertFalse(marker.exists())

    def test_preferred_port_used_when_renewing(self):
        runner = FakeRunner()
        natpmp.discover("10.2.0.1", "wgsecure", runner,
                        preferred={"tcp": 36132, "udp": 36131})
        requested = [x for x in runner.calls if x[0] == "/usr/bin/natpmpc"]
        self.assertEqual([(x[-2], x[-4]) for x in requested],
                         [("tcp", "36132"), ("udp", "36131")])

    def test_wrong_local_port_or_protocol_rejected(self):
        self.assertIsNone(natpmp.parse_mapping(
            "Mapped public port 36131 protocol UDP to local port 6882 lifetime 120", "udp"))
        self.assertIsNone(natpmp.parse_mapping(
            "Mapped public port 36131 protocol TCP to local port 6881 lifetime 120", "udp"))
        self.assertIsNone(natpmp.parse_mapping(
            "Mapped public port 36131 protocol UDP to local port 6881 lifetime 0", "udp"))

    def test_revoke_protocols_independently(self):
        runner = FakeRunner()
        result = natpmp.revoke("10.2.0.1", "wgsecure", {"udp": 36131}, runner)
        self.assertEqual(result["revoked"], ["udp"])
        calls = [x for x in runner.calls if x[0] == "/usr/bin/natpmpc"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-1], "0")

if __name__ == "__main__":
    unittest.main()
