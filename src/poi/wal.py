"""Proxy write-ahead log: every egress/dns/ingress event is durable before traffic moves."""
from __future__ import annotations

import base64
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path

from poi import canonical as c
from poi import evidence

WAL_NAME = "events.jsonl"


def _norm_headers(headers: list[tuple[str, str]]) -> bytes:
    return c.canonical_json(sorted((k.lower(), v) for k, v in headers))


@dataclass
class WalEntry:
    kind: str      # "egress" | "dns" | "ingress"
    seq: int
    element: bytes


class WalWriter:
    """Thread-safe; shared by the HTTP addon and the DNS stub so `seq` is one counter.

    With a `sealer` (sealed mode) evidence and client-data fields are encrypted before they are written.
    """

    def __init__(self, wal_dir: Path, evidence_dir: Path, sealer=None) -> None:
        self.path = Path(wal_dir) / WAL_NAME
        self.evidence_dir = Path(evidence_dir)
        self.sealer = sealer
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.seq = self._recover()

    def _put(self, data: bytes) -> str:
        return evidence.put(self.evidence_dir, self.sealer.seal_evidence(data) if self.sealer else data)

    def _el(self, element: bytes) -> bytes:
        return self.sealer.seal_element(element) if self.sealer else element

    def _recover(self) -> int:
        if not self.path.exists():
            return 0
        raw = self.path.read_bytes()
        complete = raw[: raw.rfind(b"\n") + 1]
        if len(complete) != len(raw):  # torn final write: drop it
            with open(self.path, "r+b") as f:
                f.truncate(len(complete))
        seq = 0
        for line in complete.splitlines():
            d = json.loads(line)
            if d["kind"] != "ingress":
                seq = max(seq, d["seq"])
        return seq

    def _append(self, kind: str, seq: int, element: bytes) -> None:
        line = c.canonical_json({"kind": kind, "seq": seq,
                                 "element": base64.b64encode(element).decode("ascii")}) + b"\n"
        with open(self.path, "ab") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    def record_egress(self, t: str, method: str, host: str, path: str,
                      headers: list[tuple[str, str]], body: bytes, verdict: str, reason: str) -> int:
        """Store evidence, then append the element. Raises OSError on failure: caller must block."""
        hd = self._put(_norm_headers(headers))
        bd = self._put(body)
        with self._lock:
            seq = self.seq + 1
            self._append("egress", seq, self._el(c.egress_element(seq, t, method, host, path, hd, bd, verdict, reason)))
            self.seq = seq
        return seq

    def record_dns(self, t: str, name: str, qtype: str, verdict: str) -> int:
        with self._lock:
            seq = self.seq + 1
            self._append("dns", seq, self._el(c.dns_element(seq, t, name, qtype, verdict)))
            self.seq = seq
        return seq

    def record_ingress(self, seq: int, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        hd = self._put(_norm_headers(headers))
        bd = self._put(body)
        with self._lock:
            self._append("ingress", seq, c.ingress_element(seq, status, hd, bd))


class WalReader:
    """Daemon side: yields only complete lines, remembers its byte offset."""

    def __init__(self, wal_dir: Path) -> None:
        self.path = Path(wal_dir) / WAL_NAME
        self.offset = 0

    def read_new(self) -> list[WalEntry]:
        if not self.path.exists():
            return []
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            raw = f.read()
        complete = raw[: raw.rfind(b"\n") + 1]
        self.offset += len(complete)
        out = []
        for line in complete.splitlines():
            d = json.loads(line)
            out.append(WalEntry(d["kind"], d["seq"], base64.b64decode(d["element"])))
        return out
