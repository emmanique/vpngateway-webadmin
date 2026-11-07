"""Upstream router UPnP never outlives selected DIRECT host DNAT."""
import contextlib
import importlib.util
from pathlib import Path
from unittest.mock import patch
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "vpngw-policy-agent.py"
SPEC = importlib.util.spec_from_file_location("vpngw_policy_agent_upnp_test", SOURCE)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class UpnpReconcileTests(unittest.TestCase):
    def test_direct_upnp_starts_only_after_verified_internal_dnat(self):
        events = []
        class Reconciler:
            def load_owner(self, base):
                return "host-a"
            def load_owner_upnp(self, base):
                return True
            def reconcile(self, *args, **kwargs):
                events.append("dnat_confirmed")
                return {"applied":True,"route":"direct"}
        state={"status":"active", "plan":{
            "destination":"direct", "registered_mac":"aa:bb:cc:dd:ee:ff"}}
        with (patch.object(agent, "_port_reconciler", return_value=Reconciler()),
              patch.object(agent, "read_state", return_value=state),
              patch.object(agent, "_set_kernel_identity_guard"),
              patch.object(agent, "_direct_igd_reconcile",
                 side_effect=lambda owner, mode: (
                     events.append("upnp_"+mode) or {"mapping_verified":True})),
              patch.object(agent, "BASE", Path("/tmp"))):
            # The function writes its runtime record; avoid the actual FS by
            # running against an isolated temporary directory in the test.
            import tempfile
            with tempfile.TemporaryDirectory() as directory, patch.object(
                    agent, "BASE", Path(directory)):
                record = agent.reconcile_forwarding_owner()
        self.assertEqual(events, ["dnat_confirmed", "upnp_apply"])
        self.assertTrue(record["upnp"]["mapping_verified"])

    def test_opt_out_removes_internal_dnat_before_igd_lease(self):
        events=[]
        class Forward:
            def apply(self, *args, **kwargs):
                events.append("remove_internal_dnat")
        class Reconciler:
            forward=Forward()
            def load_owner(self, base):
                return "host-a"
            def load_owner_upnp(self, base):
                return True
            def revoke_previous_lease(self, base, owner):
                return {"revoked":[]}
            def save_owner(self, base, owner, **kwargs):
                events.append("save_disabled")
        def revoke(owner, mode):
            events.append("revoke_upstream")
            return {"mapping_verified":True}
        with (patch.object(agent, "file_lock", lambda: contextlib.nullcontext()),
              patch.object(agent, "_port_reconciler", return_value=Reconciler()),
              patch.object(agent, "_direct_igd_reconcile", side_effect=revoke),
              patch.object(agent, "reconcile_forwarding_owner",
                           return_value={"applied":False})):
            agent.dispatch({"id":"host-a","action":"port_reconcile",
                            "selected":False,"upnp_enabled":False})
        self.assertEqual(events[:3], [
            "remove_internal_dnat","revoke_upstream","save_disabled"])


if __name__=="__main__":
    unittest.main()
