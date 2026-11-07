import pytest

from port_forward_plan import PortForwardPlanError, build_port_forward_plan


def test_direct_tcp_udp_and_exclusive():
    policies = {"a": {"host_ip": "192.168.1.199", "destination": "direct",
                       "port_forward_enabled": True},
                "b": {"host_ip": "192.168.1.229", "destination": "direct"}}
    plan = build_port_forward_plan(policies)
    assert plan["forwarding"]["host_ip"] == "192.168.1.199"
    assert {p["protocol"] for p in plan["forwarding"]["mappings"]} == {"tcp", "udp"}
    assert all(p["external_port"] == 6881 for p in plan["forwarding"]["mappings"])
    assert len(plan["upnp"]) == 2


def test_duplicate_forwarding_rejected():
    policies = {str(x): {"host_ip": f"192.168.1.{x}", "destination": "direct",
                         "port_forward_enabled": True} for x in (20, 21)}
    with pytest.raises(PortForwardPlanError):
        build_port_forward_plan(policies)


def test_vpn_partial_discovery_never_assumes_tcp():
    policies = {"a": {"host_ip": "192.168.1.199", "destination": "proton",
                       "port_forward_enabled": True}}
    plan = build_port_forward_plan(policies, vpn_external_ports={"proton": {"udp": 36131}})
    assert plan["forwarding"] is None
    assert plan["status"] == "vpn_tcp_udp_mapping_incomplete"
    assert plan["remove_stale_forwarding"] is True
    assert build_port_forward_plan(policies)["status"] == "vpn_tcp_udp_mapping_incomplete"


def test_deselect_or_delete_removes_mapping():
    p = {"a": {"host_ip": "192.168.1.199", "destination": "direct",
               "port_forward_enabled": False}}
    assert build_port_forward_plan(p)["forwarding"] is None
    assert build_port_forward_plan({})["remove_stale_forwarding"] is True


def test_blocked_does_not_map_or_offer_upnp():
    p = {"a": {"host_ip": "192.168.1.199", "destination": "blocked",
               "port_forward_enabled": True}}
    plan = build_port_forward_plan(p)
    assert plan["forwarding"] is None
    assert plan["upnp"] == []


def test_invalid_port_and_ip_are_not_mapped():
    p = {"a": {"host_ip": "192.168.1.199", "destination": "vpn",
               "port_forward_enabled": True}}
    assert build_port_forward_plan(p, vpn_external_ports={"vpn": {"udp": 99999}})["forwarding"] is None
    p["a"]["host_ip"] = "127.0.0.1"
    with pytest.raises(PortForwardPlanError):
        build_port_forward_plan(p)


def test_provider_tcp_udp_port_conflict_requires_no_forwarding():
    p = {"a": {"host_ip": "192.168.1.199", "destination": "proton",
               "port_forward_enabled": True}}
    plan = build_port_forward_plan(p, vpn_external_ports={"proton": {"tcp": 36131, "udp": 36132}})
    assert plan["forwarding"] is None
    assert plan["status"] == "vpn_ports_conflict"
