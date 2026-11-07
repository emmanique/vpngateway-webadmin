import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location("route",Path(__file__).resolve().parents[1]/"scripts"/"vpngw-vpn-host-dns-route-plan.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class HostDnsRouteTests(unittest.TestCase):
 def test_worker_route_precedes_default(self):
  result=m.render("192.168.1.226","172.31.83.53","brvg6eb314b8b6","tun6eb314b8b6",28690,18690,"wlp2s0","172.31.83.53 dev brvg6eb314b8b6 src 172.31.83.1")
  self.assertIn("unreachable",result["commands"][0])
  self.assertIn("172.31.83.53/32",result["commands"][1])
  self.assertFalse(result["applied"])
 def test_wrong_bridge_fails(self):
  with self.assertRaises(ValueError):
   m.render("192.168.1.226","172.31.83.53","brvg6eb314b8b6","tun6eb314b8b6",28690,18690,"wlp2s0","172.31.83.53 dev wlp2s0")
