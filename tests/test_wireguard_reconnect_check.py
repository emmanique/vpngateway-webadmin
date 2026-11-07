import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location("wgcheck",Path(__file__).resolve().parents[1]/"scripts"/"vpngw-wireguard-reconnect-check.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Result:
 def __init__(self,code=0,stdout=""):self.returncode=code;self.stdout=stdout
class WGRecovery(unittest.TestCase):
 def test_missing_interface(self):
  with patch.object(m,"run",return_value=Result(1)):
   self.assertEqual(m.health(),(False,"interface_missing"))
 def test_recent_handshake(self):
  with patch.object(m,"run",side_effect=[Result(),Result(stdout="peer 1950000000")]),patch.object(m.time,"time",return_value=1950000015):
   self.assertEqual(m.health(),(True,"handshake_recent"))
 def test_stale_handshake_successful_probe(self):
  with patch.object(m,"run",side_effect=[Result(),Result(stdout="peer 100"),Result()]),patch.object(m.time,"time",return_value=1950000015):
   self.assertEqual(m.health(),(True,"tunnel_probe_ok"))
 def test_stale_handshake_failed_probe(self):
  with patch.object(m,"run",side_effect=[Result(),Result(stdout="peer 100"),Result(1)]),patch.object(m.time,"time",return_value=1950000015):
   self.assertEqual(m.health(),(False,"stale_handshake_and_failed_probe"))
