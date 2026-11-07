"""Offline DHCP-renumber watcher: no mutation after one observation."""
import unittest
from rebind_watcher import RebindWatcher

POLICY = {"id":"host-a", "host_ip":"192.168.1.199",
          "registered_mac":"aa:bb:cc:dd:ee:ff", "status":"active"}
EVIDENCE = {"previous_ip":"192.168.1.199",
            "candidate_ip":"192.168.1.205",
            "registered_mac":"aa:bb:cc:dd:ee:ff",
            "verified_neighbor":True, "changed":True}


class WatcherTests(unittest.TestCase):
    def test_requires_two_consecutive_identical_fresh_observations(self):
        watcher = RebindWatcher()
        applied = []
        run = lambda: watcher.poll([POLICY],
            preflight=lambda pid: dict(EVIDENCE),
            pending=lambda pid: {"pending":False},
            apply=lambda pid, ip: applied.append((pid,ip)))
        self.assertEqual(run(), [("host-a", "observing")])
        self.assertEqual(applied, [])
        self.assertEqual(run(), [("host-a", "rebound")])
        self.assertEqual(applied, [("host-a","192.168.1.205")])

    def test_candidate_change_resets_observation(self):
        watcher = RebindWatcher()
        applied = []
        newer = dict(EVIDENCE, candidate_ip="192.168.1.206")
        watcher.poll([POLICY], preflight=lambda p: EVIDENCE,
                     pending=lambda p: {"pending":False},
                     apply=lambda p,ip: applied.append(ip))
        response = watcher.poll([POLICY], preflight=lambda p: newer,
                                pending=lambda p: {"pending":False},
                                apply=lambda p,ip: applied.append(ip))
        self.assertEqual(response, [("host-a", "observing")])
        self.assertEqual(applied, [])

    def test_old_or_incorrect_mac_cannot_trigger_rebind(self):
        watcher = RebindWatcher()
        applied=[]
        for bad in (dict(EVIDENCE, registered_mac="aa:bb:cc:dd:ee:01"),
                    dict(EVIDENCE, verified_neighbor=False),
                    dict(EVIDENCE, previous_ip="192.168.1.222")):
            for _ in range(2):
                watcher.poll([POLICY], preflight=lambda p: bad,
                             pending=lambda p: {"pending":False},
                             apply=lambda p,ip: applied.append(ip))
        self.assertEqual(applied,[])

    def test_durable_pending_journal_resumes_without_second_observation(self):
        watcher = RebindWatcher()
        applied=[]
        pending={"pending":True, "previous_ip":"192.168.1.199",
                 "candidate_ip":"192.168.1.205","mac":POLICY["registered_mac"]}
        result=watcher.poll([POLICY],
            preflight=lambda p: self.fail("No preflight on matching pending journal"),
            pending=lambda p: pending,
            apply=lambda p,ip: applied.append(ip))
        self.assertEqual(result,[("host-a","pending_resumed")])
        self.assertEqual(applied,["192.168.1.205"])

    def test_one_host_failure_does_not_interrupt_other_hosts(self):
        watcher = RebindWatcher()
        second = dict(POLICY, id="host-b", host_ip="192.168.1.229",
                      registered_mac="aa:bb:cc:dd:ee:01")
        results = watcher.poll([POLICY, second],
            preflight=lambda pid: (
                (_ for _ in ()).throw(RuntimeError("Agent unavailable"))
                if pid == "host-a" else
                {"previous_ip":"192.168.1.229", "candidate_ip":"192.168.1.230",
                 "registered_mac":"aa:bb:cc:dd:ee:01",
                 "verified_neighbor":True, "changed":True}),
            pending=lambda pid: {"pending":False},
            apply=lambda pid, ip: None)
        self.assertEqual(results, [("host-a","rebind_error"),
                                  ("host-b","observing")])

    def test_conflicting_pending_journal_never_mutates_kernel(self):
        watcher=RebindWatcher()
        result=watcher.poll([POLICY],
            preflight=lambda p: self.fail("Preflight should not run"),
            pending=lambda p: {"pending":True, "previous_ip":"192.168.1.229",
                               "candidate_ip":"192.168.1.230","mac":"aa:bb:cc:dd:ee:01"},
            apply=lambda p,ip: self.fail("Unsafe rebind"))
        self.assertEqual(result,[("host-a","pending_conflict")])

if __name__=="__main__":
    unittest.main()
