"""Simulated independent network rollback deadline regression tests."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[3] / 'scripts' / 'network-rollback-timer.py'
spec = importlib.util.spec_from_file_location('network_rollback_timer', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NetworkRollbackTimerTests(unittest.TestCase):
    def test_no_confirmation_keeps_armed(self):
        self.assertEqual(module.decide(100, 160, 120)['action'], 'keep_armed')

    def test_expiry_requires_rollback(self):
        self.assertEqual(module.decide(100, 160, 160)['action'], 'rollback_required')

    def test_external_probe_alone_not_enough(self):
        self.assertEqual(module.decide(100, 160, 120, True, False)['action'], 'keep_armed')

    def test_confirmation_without_probe_not_enough(self):
        self.assertEqual(module.decide(100, 160, 120, False, True)['action'], 'keep_armed')

    def test_both_checks_cancel_before_expiry(self):
        self.assertEqual(module.decide(100, 160, 120, True, True)['action'], 'cancel_rollback')

    def test_late_confirmation_cannot_cancel(self):
        self.assertEqual(module.decide(100, 160, 161, True, True)['action'], 'rollback_required')

    def test_invalid_deadline_rejected(self):
        with self.assertRaisesRegex(ValueError, 'deadline_must_follow_arm_time'):
            module.decide(100, 100, 100)

    def test_future_arm_time_rejected(self):
        with self.assertRaisesRegex(ValueError, 'clock_before_arm_time'):
            module.decide(100, 160, 99)


if __name__ == '__main__':
    unittest.main()
