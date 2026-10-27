"""Owner-side mirror: copy a run from a Source, verify every checkpoint as it arrives, keep the evidence.

The mirror directory has the same layout as a run directory, so `poi verify` / `poi report` work on it.
"""
from __future__ import annotations

import json
import math
import os
import threading
import time
from pathlib import Path
from typing import Callable

from poi import canonical as c
from poi import evidence
from poi import policy as pol
from poi.assess import Snapshot, Verdict, assess
from poi.fingerprint import FingerprintSet
from poi.seal.sealer import EV_MAGIC, display_fields, is_sealed
from poi.source import NotFound, Source, SourceError
from poi.verify import ChainVerifier, Event, VerifyError, parse_delta

RETRIES = 3


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def evidence_digests(ops: list[tuple[str, str, bytes]]) -> list[str]:
    """Evidence a checkpoint's delta refers to: config JSON, egress headers/body, ingress headers/body."""
    out = []
    for op, acc, element in ops:
        f = c.decode(element)
        if op == "add" and f[0] == "config":
            out.append(f[1])
        elif f[0] == "egress":
            out += [f[6], f[7]]
        elif f[0] == "ingress":
            out += [f[3], f[4]]
    return out


class Mirror:
    def __init__(self, mirror_dir: Path, source: Source, pubkey_hex: str,
                 fingerprints: FingerprintSet | None = None, source_label: str = "",
                 monotonic: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 sealer=None) -> None:
        self.dir = Path(mirror_dir)
        self.source = source
        self.pubkey_hex = pubkey_hex
        self.fingerprints = fingerprints
        self.monotonic, self.sleep = monotonic, sleep
        self.lock = threading.RLock()
        self.changed = threading.Condition(self.lock)
        self.version = 0
        for d in ("ledger", "delta", "evidence"):
            (self.dir / d).mkdir(parents=True, exist_ok=True)
        pk = self.dir / "pubkey"
        if pk.exists() and pk.read_text().strip() != pubkey_hex:
            raise ValueError(f"mirror {self.dir} was created for a different operator key")
        pk.write_text(pubkey_hex + "\n")
        (self.dir / "source.json").write_text(json.dumps({"source": source_label}))
        self.started = monotonic()
        self.last_received: float | None = None
        self.source_down_since: float | None = None
        self.source_error: str | None = None
        self.error: VerifyError | None = None
        self.runtime: dict | None = None
        self.hits: dict[int, tuple[str, list[str]]] = {}     # egress seq -> (verdict, sources)
        self.acks: set[int] = set(json.loads((self.dir / "acks.json").read_text())) \
            if (self.dir / "acks.json").exists() else set()
        self.sealer = sealer
        self.policy = self._load_policy()
        self._copy_sealed_doc()
        self.verifier = ChainVerifier(pubkey_hex, self.policy, sealer)
        self.replay_local()

    # -- setup -------------------------------------------------------------------
    def _load_policy(self) -> pol.Policy:
        p = self.dir / "policy.yaml"
        if not p.exists():
            _write_atomic(p, self.source.policy())
        return pol.load(p)

    def _copy_sealed_doc(self) -> None:
        """Keep sealed.json next to the mirrored run so `poi verify MIRROR --client-key` works."""
        p = self.dir / "sealed.json"
        if p.exists():
            return
        try:
            _write_atomic(p, self.source.sealed())
        except SourceError:
            pass                                    # not a sealed run

    def fields(self, f: list[str]) -> list[str]:
        """Element fields for display: decrypted with the client key, 🔒 without it."""
        return self.sealer.open_fields(f) if self.sealer is not None else display_fields(f)

    def evidence(self, digest: str) -> bytes | None:
        data = self._get_local(digest)
        if data is None:
            return None
        if self.sealer is not None:
            return self.sealer.open_evidence(data)
        return None if data.startswith(EV_MAGIC) else data

    def _get_local(self, digest: str) -> bytes | None:
        return evidence.get(self.dir / "evidence", digest)

    def _after_feed(self, events: list[Event]) -> None:
        if self.fingerprints is None:
            return
        for ev in events:
            if ev.domain != "egress":
                continue
            if self.sealer is None and any(is_sealed(x) for x in ev.fields):
                continue                            # nothing to scan without the client key
            f = self.fields(ev.fields)
            body = self.evidence(f[7]) or b""
            found = self.fingerprints.scan(body + b" " + f[5].encode())
            if found:
                self.hits[ev.seq] = (f[8], sorted(found))

    def replay_local(self) -> None:
        """Re-verify everything already in the mirror (restart, or local tampering)."""
        seq = 0
        while (p := self.dir / "ledger" / f"{seq:06d}.json").exists():
            try:
                cp = json.loads(p.read_bytes())
                raw = (self.dir / "delta" / f"{seq:06d}.jsonl").read_bytes()
                self._after_feed(self.verifier.feed(cp, raw, self._get_local))
            except VerifyError as e:
                self.error = e
                return
            except (FileNotFoundError, json.JSONDecodeError) as e:
                self.error = VerifyError(11, seq, f"mirror file unreadable: {e}")
                return
            seq += 1

    # -- fetching ------------------------------------------------------------------
    def _retry(self, fn, *args):
        delay = 0.5
        for attempt in range(RETRIES):
            try:
                return fn(*args)
            except NotFound:
                if attempt == RETRIES - 1:
                    return None
            except SourceError:
                if attempt == RETRIES - 1:
                    raise
            self.sleep(delay)
            delay *= 2
        return None

    def _fetch_evidence(self, digest: str) -> None:
        if self._get_local(digest) is not None:
            return
        data = self._retry(self.source.evidence, digest)
        if data is not None and c.b2b256(data) == digest:   # never store bytes under a wrong name
            _write_atomic(self.dir / "evidence" / f"{digest}.bin", data)

    def _ingest(self, cp: dict) -> None:
        seq = self.verifier.next_checkpoint
        raw = self._retry(self.source.delta, seq)
        if raw is None:
            raise VerifyError(12, seq, "operator did not provide the delta file")
        _write_atomic(self.dir / "delta" / f"{seq:06d}.jsonl", raw)
        _write_atomic(self.dir / "ledger" / f"{seq:06d}.json", c.canonical_json(cp))
        try:
            digests = evidence_digests(parse_delta(cp, raw))
        except (VerifyError, ValueError, KeyError):
            digests = []                                        # feed() reports the precise error
        for d in digests:
            self._fetch_evidence(d)
        events = self.verifier.feed(cp, raw, self._get_local)
        with self.lock:
            self._after_feed(events)

    def sync_once(self, wait: float = 25.0) -> int:
        """Fetch and verify new checkpoints. Returns how many were verified."""
        if self.error is not None:
            return 0
        try:
            cps = self.source.checkpoints(self.verifier.next_checkpoint, wait)
            n = 0
            for cp in cps:
                if cp.get("seq") != self.verifier.next_checkpoint:
                    raise VerifyError(11, cp.get("seq"), f"operator sent checkpoint out of order "
                                                         f"(expected {self.verifier.next_checkpoint})")
                self._ingest(cp)
                n += 1
                with self.lock:
                    self.last_received = self.monotonic()
                    self._bump()
            with self.lock:
                self.source_down_since, self.source_error = None, None
            return n
        except VerifyError as e:
            with self.lock:
                self.error = e
                self._bump()
            return 0
        except SourceError as e:
            with self.lock:
                if self.source_down_since is None:
                    self.source_down_since = self.monotonic()
                self.source_error = str(e)
                self._bump()
            raise

    def refresh_runtime(self) -> None:
        try:
            rt = self.source.runtime()
        except SourceError:
            return
        with self.lock:
            if rt != self.runtime:
                self.runtime = rt
                self._bump()

    def run(self, stop: threading.Event, wait: float = 25.0) -> None:
        """Background loop: long-poll for checkpoints; runtime declarations are polled separately."""
        backoff = 1.0
        while not stop.is_set():
            try:
                self.sync_once(wait)
                backoff = 1.0
                if self.error is not None:
                    stop.wait(self.policy.tick_seconds)
            except SourceError:
                stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)

    def run_runtime(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self.refresh_runtime()
            stop.wait(self.policy.tick_seconds)

    # -- state for the UI -------------------------------------------------------------
    def _bump(self) -> None:
        self.version += 1
        self.changed.notify_all()

    def ack(self, seq: int) -> bool:
        with self.lock:
            if seq not in self.hits:
                return False
            self.acks.add(seq)
            _write_atomic(self.dir / "acks.json", json.dumps(sorted(self.acks)).encode())
            self._bump()
            return True

    def snapshot(self) -> Snapshot:
        with self.lock:
            unbounded = any(math.isinf(pol.endpoint_capacity(e)) for e in self.policy.endpoints)
            return Snapshot(
                error=str(self.error) if self.error else None,
                allowed_hits=sorted(s for s, (v, _) in self.hits.items() if v == "allow"),
                blocked_hits=sorted(s for s, (v, _) in self.hits.items() if v != "allow"),
                acked=set(self.acks), last_received=self.last_received, started=self.started,
                source_down_since=self.source_down_since, tick_seconds=self.policy.tick_seconds,
                unbounded_channel=unbounded,
                run_finished=bool(self.runtime and self.runtime.get("status") == "exited"))

    def verdict(self) -> Verdict:
        return assess(self.snapshot(), self.monotonic())
