"""Daemon core: turns state changes and proxy WAL events into signed checkpoints."""
from __future__ import annotations

import json
from typing import Callable

from poi import canonical as c
from poi import evidence
from poi.gate import utcnow
from poi.ledger import DeltaOp, Ledger
from poi.lthash import LtHash
from poi.policy import Policy, config_violations
from poi.publish import Publisher
from poi.state import StateTracker
from poi.wal import WalReader


class Engine:
    def __init__(self, ledger: Ledger, tracker: StateTracker, wal: WalReader, publisher: Publisher,
                 policy: Policy, container: dict, *, clock: Callable[[], str] = utcnow,
                 on_violation: Callable[[list[str]], None] = lambda v: None,
                 full_scan_every: int = 60) -> None:
        self.ledger, self.tracker, self.wal, self.publisher = ledger, tracker, wal, publisher
        self.policy, self.container, self.clock = policy, container, clock
        self.on_violation = on_violation
        self.full_scan_every = full_scan_every
        self.accs = {a: LtHash() for a in ("state", "egress", "ingress")}
        self.counts = {"egress": 0, "ingress": 0}
        self.egress_seq = 0
        self.ingress_seen: set[int] = set()
        self.ticks = 0
        self.violations: list[str] = []

    def _state_ops(self, full: bool) -> list[DeltaOp]:
        ops = self.tracker.update(full)
        evidence.put(self.ledger.evidence_dir, self.tracker.last_config)
        self.violations = config_violations(json.loads(self.tracker.last_config), self.policy)
        return ops

    def _wal_ops(self) -> list[DeltaOp]:
        ops = []
        for e in self.wal.read_new():
            if e.kind == "ingress":
                if e.seq in self.ingress_seen:
                    continue
                self.ingress_seen.add(e.seq)
                ops.append(DeltaOp("add", "ingress", e.element))
                self.counts["ingress"] += 1
            else:
                if e.seq <= self.egress_seq:
                    continue
                self.egress_seq = e.seq
                ops.append(DeltaOp("add", "egress", e.element))
                self.counts["egress"] += 1
        return ops

    def _commit(self, ops: list[DeltaOp], restart: bool = False) -> dict:
        for op in ops:
            (self.accs[op.acc].add if op.op == "add" else self.accs[op.acc].sub)(op.element)
        last = self.ledger.last()
        t = self.clock() if last is None else max(self.clock(), last["t"])  # never go backwards
        cp = self.ledger.append(t=t, container=self.container, policy_digest=self.policy.digest,
                                accs=self.accs, counts=self.counts, ops=ops, restart=restart)
        self.publisher.publish(cp)
        if self.violations:
            self.on_violation(self.violations)
        return cp

    def genesis(self) -> dict:
        self.tracker.load_image()
        return self._commit(self._state_ops(full=False))

    def tick(self) -> dict:
        self.ticks += 1
        full = self.full_scan_every > 0 and self.ticks % self.full_scan_every == 0
        return self._commit(self._state_ops(full) + self._wal_ops())

    def resume(self) -> dict:
        """Daemon restart: rebuild in-memory state from the ledger, then full rescan."""
        last = self.ledger.last()
        state: dict[bytes, int] = {}
        for seq in range(last["seq"] + 1):
            for op in self.ledger.read_delta(seq):
                if op.acc == "state":
                    state[op.element] = state.get(op.element, 0) + (1 if op.op == "add" else -1)
                elif op.acc == "egress":
                    self.egress_seq = max(self.egress_seq, int(c.decode(op.element)[1]))
                else:
                    self.ingress_seen.add(int(c.decode(op.element)[1]))
        self.tracker.restore_index(e for e, n in state.items() if n > 0)
        self.tracker.load_image()
        for a in self.accs:
            self.accs[a] = LtHash.from_b64(last[a]["vec"])
        self.counts = {"egress": last["egress"]["count"], "ingress": last["ingress"]["count"]}
        return self._commit(self._state_ops(full=True) + self._wal_ops(), restart=True)
