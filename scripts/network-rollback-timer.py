#!/usr/bin/env python3
"""Fail-closed rollback timer simulator; does not invoke systemd or change network.

Models arming, expiry and confirmation independently of host connectivity.
Actual systemd scheduling is deliberately not enabled until isolated testing.
"""
import argparse
import json


def decide(armed_at, deadline, now, external_probe_verified=False,
           confirmation_received=False):
    if not all(isinstance(x, (int, float)) and not isinstance(x, bool)
               for x in (armed_at, deadline, now)):
        raise ValueError('invalid_timestamp')
    if deadline <= armed_at:
        raise ValueError('deadline_must_follow_arm_time')
    if now < armed_at:
        raise ValueError('clock_before_arm_time')
    expired = now >= deadline
    confirmed = bool(external_probe_verified and confirmation_received and not expired)
    action = 'cancel_rollback' if confirmed else ('rollback_required' if expired else 'keep_armed')
    return {'mode': 'simulation_only', 'action': action,
            'expired': expired, 'external_probe_verified': bool(external_probe_verified),
            'confirmation_received': bool(confirmation_received),
            'systemd_timer_created': False, 'network_changes_applied': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--armed-at', type=float, required=True)
    parser.add_argument('--deadline', type=float, required=True)
    parser.add_argument('--now', type=float, required=True)
    parser.add_argument('--external-probe-verified', action='store_true')
    parser.add_argument('--confirmation-received', action='store_true')
    args = parser.parse_args()
    print(json.dumps(decide(args.armed_at, args.deadline, args.now,
                            args.external_probe_verified, args.confirmation_received), indent=2))


if __name__ == '__main__':
    main()
