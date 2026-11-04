"""Fail-closed, opt-in, two-observation IPv4/MAC reconciler.

Runs in the single-worker WebAdmin API process and calls the existing
privileged two-phase transaction. No network changes on a single ARP sample.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class RebindWatcher:
    observations: dict = field(default_factory=dict)

    def poll(self, policies, *, preflight, pending, apply):
        """Execute one pass using callbacks injectable for regression tests.

        Policies are copied from persistent API assignments. The pending
        callback checks the privileged kernel transaction journal.
        """
        results = []
        active = set()
        for policy in policies:
            try:
                pid = policy.get("id")
                old = policy.get("host_ip")
                mac = str(policy.get("registered_mac") or "").lower()
                if (not pid or not old or not mac
                        or policy.get("status") != "active"):
                    continue
                active.add(pid)
                inflight = pending(pid)
                if inflight.get("pending"):
                    if (inflight.get("mac") != mac or
                            old not in (inflight.get("previous_ip"),
                                        inflight.get("candidate_ip"))):
                        results.append((pid, "pending_conflict"))
                        continue
                    candidate = inflight.get("candidate_ip")
                    # Crash recovery runs immediately; only a matching persisted
                    # MAC/IP journal can authorise a repeat prepare or commit.
                    apply(pid, candidate)
                    self.observations.pop(pid, None)
                    results.append((pid, "pending_resumed"))
                    continue
                evidence = preflight(pid)
                candidate = evidence.get("candidate_ip")
                if (not evidence.get("changed")
                        or not evidence.get("verified_neighbor")
                        or evidence.get("registered_mac") != mac
                        or evidence.get("previous_ip") != old
                        or not candidate or candidate == old):
                    self.observations.pop(pid, None)
                    continue
                signature = (old, candidate, mac)
                previous = self.observations.get(pid)
                if previous == signature:
                    apply(pid, candidate)
                    self.observations.pop(pid, None)
                    results.append((pid, "rebound"))
                else:
                    self.observations[pid] = signature
                    results.append((pid, "observing"))
            except Exception:
                pid = policy.get("id") if isinstance(policy, dict) else None
                self.observations.pop(pid, None)
                results.append((pid, "rebind_error"))
        for stale in set(self.observations) - active:
            self.observations.pop(stale, None)
        return results
