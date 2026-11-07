import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
s=importlib.util.spec_from_file_location('observer',Path(__file__).resolve().parents[1]/'scripts'/'vpngw-vpn-client-route-observer.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def runner(output,rc=0):
 return lambda *args,**kwargs:SimpleNamespace(stdout=output,returncode=rc)
class ObserverTests(unittest.TestCase):
 def test_direct_is_not_vpn_proof(self):
  r=m.check('caio','192.168.1.226','tun6eb314b8b6',28690,'wlp2s0',runner=runner('1.1.1.1 from 192.168.1.226 via 192.168.1.1 dev wlp2s0'))
  self.assertTrue(r['kernel_direct_route'])
  self.assertFalse(r['kernel_vpn_route'])
  self.assertFalse(r['client_egress_verified'])
 def test_vpn_route_is_not_client_egress_proof(self):
  r=m.check('teste','192.168.1.227','tuna713bb390e',39923,'wlp2s0',runner=runner('1.1.1.1 from 192.168.1.227 dev tuna713bb390e table 39923'))
  self.assertTrue(r['kernel_vpn_route'])
  self.assertFalse(r['client_egress_verified'])
 def test_failed_lookup_fails_closed(self):
  r=m.check('teste','192.168.1.227','tuna713bb390e',39923,'wlp2s0',runner=runner('',rc=2))
  self.assertFalse(r['route_lookup_ok'])
  self.assertFalse(r['cutover_enabled'])

 def test_arbitrary_host_and_interface(self):
  r=m.check('office-route','10.44.1.77','tunabc123',22010,'eth1',wan='eth0',runner=runner('1.1.1.1 from 10.44.1.77 dev tunabc123 table 22010'))
  self.assertTrue(r['kernel_vpn_route'])
  self.assertFalse(r['client_egress_verified'])
