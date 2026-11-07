"""Host exclusive forwarding must follow all route transitions, including systemd rollback."""
import contextlib
import json
import tempfile
import importlib.util
from pathlib import Path
from unittest.mock import patch
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/vpngw-policy-agent.py"
SPEC = importlib.util.spec_from_file_location("vpngw_policy_agent_port_transition", SOURCE)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class PortOwner:
    def __init__(self, events):
        self.events = events
    def load_owner(self, base):
        return "host-a"
    def load_owner_provider(self, base):
        return "proton"
    def load_owner_upnp(self, base):
        return False
    def save_owner(self, base, owner, *, provider, upnp_enabled=False):
        self.events.append(("owner_provider", provider))


class RouteForwardingTests(unittest.TestCase):
    def test_suspension_invalidates_status_before_revoking_old_provider(self):
        events = []
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            state = base / "port-forward" / "runtime.json"
            state.parent.mkdir(parents=True)
            original = {"owner": "host-a", "status": "nat_rules_verified",
                        "applied": True, "route": "vpn-proton-wg",
                        "provider_lease": True, "gateway": "10.2.0.1",
                        "vpn_interface": "wgsecure",
                        "external_ports": {"tcp": 37718, "udp": 37718}}
            state.write_text(json.dumps(original))
            class FakeForward:
                def apply(self, *args, **kwargs):
                    events.append(("remove_dnat", None))
            class Reconciler:
                forward = FakeForward()
                def load_owner(self, root):
                    return "host-a"
                def load_owner_upnp(self, root):
                    return False
                def revoke_previous_lease(self, root, pid, *, previous_runtime):
                    observed = json.loads(state.read_text())
                    events.append(("revoke", previous_runtime["external_ports"]))
                    assert observed["applied"] is False
                    assert observed["external_ports"] == {}
            with (patch.object(agent, "BASE", base),
                  patch.object(agent, "_port_reconciler", return_value=Reconciler())):
                agent.suspend_owned_forwarding("host-a")
            self.assertEqual(events, [
                ("remove_dnat", None),
                ("revoke", {"tcp": 37718, "udp": 37718}),
            ])
            now = json.loads(state.read_text())
            self.assertEqual(now["status"], "route_transition_suspended")

    def test_owner_renewal_is_reconciled_after_each_successful_route_transition(self):
        for action, destination in [
            ("vpn_transition", "vpn-proton-ovpn"),
            ("vpn_transition", "direct"),
            ("vpn_transition", "blocked"),
            ("transition_basic", "direct"),
            ("transition_basic", "blocked"),
        ]:
            with self.subTest(action=action, destination=destination):
                events = []
                owner = PortOwner(events)
                def suspend(pid):
                    events.append(("suspend", pid))
                def transition(*args, **kwargs):
                    events.append(("transition", destination))
                    return {"status": "active", "destination": destination}
                def reconcile():
                    events.append(("reconcile", None))
                    return {"applied": False}
                with (patch.object(agent, "file_lock", lambda: contextlib.nullcontext()),
                      patch.object(agent, "_port_reconciler", return_value=owner),
                      patch.object(agent, "suspend_owned_forwarding", suspend),
                      patch.object(agent, "transition_basic", transition),
                      patch.object(agent, "vpn_transition", transition),
                      patch.object(agent, "reconcile_forwarding_owner", reconcile)):
                    payload = {"action": action, "id": "host-a",
                               "destination": destination, "provider": "generic"}
                    result = agent.dispatch(payload)
                self.assertEqual(result["destination"], destination)
                self.assertEqual(events, [
                    ("suspend", "host-a"),
                    ("transition", destination),
                    ("owner_provider", "generic"),
                    ("reconcile", None),
                ])

    def test_unattended_reversion_restores_previous_provider_and_dnat(self):
        events = []
        owner = PortOwner(events)
        saved = {"status": "active", "vpn_pending": {
            "previous": "vpn-proton-wg", "previous_dns": "10.2.0.1",
            "previous_provider": "proton", "deadline": 987654321}}
        def suspend(pid):
            events.append(("suspend", pid))
        def switch(pid, dest, dns, **kwargs):
            events.append(("transition", dest))
            return {"status": "active", "destination": dest}
        def reconcile():
            events.append(("reconcile", None))
        with (patch.object(agent, "file_lock", lambda: contextlib.nullcontext()),
              patch.object(agent, "read_state", return_value=saved),
              patch.object(agent, "_port_reconciler", return_value=owner),
              patch.object(agent, "suspend_owned_forwarding", suspend),
              patch.object(agent, "vpn_transition", switch),
              patch.object(agent, "reconcile_forwarding_owner", reconcile)):
            result = agent.revert_unconfirmed_vpn("host-a")
        self.assertEqual(result["destination"], "vpn-proton-wg")
        self.assertEqual(events, [
            ("suspend", "host-a"),
            ("transition", "vpn-proton-wg"),
            ("owner_provider", "proton"),
            ("reconcile", None),
        ])

    def test_rollback_to_blocked_if_previous_vpn_fails(self):
        events = []
        owner = PortOwner(events)
        def transition(pid, dest, dns=None, **kwargs):
            events.append(("transition", dest))
            if dest == "vpn-proton-wg":
                raise ValueError("Tunnel unavailable")
            return {"status": "active", "destination": dest}
        with (patch.object(agent, "file_lock", lambda: contextlib.nullcontext()),
              patch.object(agent, "read_state", return_value={"vpn_pending": {
                  "previous": "vpn-proton-wg", "previous_provider": "proton"}}),
              patch.object(agent, "_port_reconciler", return_value=owner),
              patch.object(agent, "suspend_owned_forwarding", lambda pid: events.append(("suspend", pid))),
              patch.object(agent, "vpn_transition", transition),
              patch.object(agent, "reconcile_forwarding_owner", lambda: events.append(("reconcile", None)))):
            result = agent.revert_unconfirmed_vpn("host-a")
        self.assertEqual(result["destination"], "blocked")
        self.assertEqual(events[-2:], [("owner_provider", "generic"), ("reconcile", None)])


if __name__ == "__main__":
    unittest.main()
