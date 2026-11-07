import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]/"scripts"
def load(file,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/file)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
vpn=load("vpngw-vpn-route-plan.py","vpn_plan")
openvpn=load("vpngw-openvpn-agent.py","openvpn_agent")
class MultiProfile(unittest.TestCase):
    def plan(self,host,interface,profile):
        return vpn.build_plan(host,"192.168.1.1","wlp2s0",interface,profile,"direct",True,False,False)
    def test_per_host_tables_unique(self):
        a=self.plan("192.168.1.226","tun6eb314b8b6","vpn-proton-openvpn")
        b=self.plan("192.168.1.227","tun6eb314b8b6","vpn-proton-openvpn")
        self.assertNotEqual(a["routing"]["table_id"],b["routing"]["table_id"])
        self.assertNotEqual(a["routing"]["priority"],b["routing"]["priority"])
    def test_openvpn_and_wireguard(self):
        for interface in ("tun6eb314b8b6","tuna713bb390e","wga509c86fbd2"):
            self.assertIn(interface,self.plan("192.168.1.227",interface,"vpn-new-profile")["firewall"]["client_forward"])
    def test_profile_validation(self):
        for profile in ("vpn-proton-openvpn","vpn-cyberghost-openvpn","vpn-new-provider-1"):
            self.assertEqual(openvpn.checkid(profile),profile)
        for bad in ("../../etc/passwd","vpn-foo;echo","vpn-","wireguard","vpn-a"*20):
            with self.subTest(bad=bad),self.assertRaises(ValueError):openvpn.checkid(bad)
    def test_fail_closed_unimplemented(self):
        plan=self.plan("192.168.1.227","tuna713bb390e","vpn-new-profile")
        self.assertFalse(plan["ready"])
        self.assertFalse(plan["applied"])
        self.assertTrue(plan["blockers"])
if __name__=="__main__":unittest.main()
