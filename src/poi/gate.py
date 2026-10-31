"""Egress decision logic, independent of mitmproxy so it can be unit-tested."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from poi.fingerprint import FingerprintSet
from poi.policy import Policy
from poi.wal import WalWriter


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class GateResult:
    verdict: str
    reason: str
    seq: int | None = None
    body: bytes = b""
    headers: list[tuple[str, str]] = field(default_factory=list)


# Credentials the workload sends with forwarded traffic (allow_all_egress): the ledger keeps that the header was
# there, not its value — the evidence is shared, the API key is not.
SECRET_HEADERS = {"authorization", "proxy-authorization", "cookie", "x-api-key", "api-key", "x-auth-token"}


def _redact(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(k, "***" if k.lower() in SECRET_HEADERS else v) for k, v in headers]


class EgressGate:
    def __init__(self, policy: Policy, wal: WalWriter, fingerprints: FingerprintSet | None = None,
                 clock: Callable[[], str] = utcnow, monotonic: Callable[[], float] = time.monotonic,
                 isolated: Callable[[], bool] = lambda: False) -> None:
        self.policy = policy
        self.isolated = isolated              # operator's kill switch: block everything from now on
        self.wal = wal
        self.fingerprints = fingerprints
        self.clock = clock
        self.monotonic = monotonic
        self._window: dict[tuple[str, str, str], deque[float]] = defaultdict(deque)

    def _rate_ok(self, key: tuple[str, str, str], limit: int | None) -> bool:
        if limit is None:
            return True
        now = self.monotonic()
        q = self._window[key]
        while q and now - q[0] >= 60:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True

    def _record(self, method, host, path, headers, body, verdict, reason) -> GateResult:
        try:
            seq = self.wal.record_egress(self.clock(), method, host, path, headers, body, verdict, reason)
        except OSError:
            return GateResult("block", "wal-failure")  # fail closed: nothing leaves unlogged
        return GateResult(verdict, reason, seq, body if verdict == "allow" else b"", headers)

    def on_connect(self, host: str) -> GateResult:
        if self.isolated():
            return self._record("CONNECT", host, "", [], b"", "block", "isolated")
        if self.policy.allow_all_egress or host in self.policy.hosts:
            return GateResult("allow", "")
        return self._record("CONNECT", host, "", [], b"", "block", "host-not-allowed")

    def on_request(self, host: str, method: str, path: str,
                   headers: list[tuple[str, str]], body: bytes) -> GateResult:
        if self.isolated():
            return self._record(method, host, path, _redact(headers), body, "block", "isolated")
        if self.policy.allow_all_egress:
            # no blocking, no canonicalisation: forwarded as sent; a fingerprint hit stays in the reason field
            hit = self.fingerprints is not None and self.fingerprints.scan(body)
            r = self._record(method, host, path, _redact(headers), body, "allow", "fingerprint" if hit else "")
            return GateResult(r.verdict, r.reason, r.seq, r.body, headers)
        d = self.policy.decide(host, method, path, body)
        if d.verdict == "allow" and self.fingerprints is not None and self.fingerprints.scan(body):
            d.verdict, d.reason = "block", "fingerprint"
        if d.verdict == "allow" and not self._rate_ok((host, method, path), d.endpoint.max_requests_per_minute):
            d.verdict, d.reason = "block", "rate-limit"
        if d.verdict == "block":
            return self._record(method, host, path, headers, body, "block", d.reason)
        fwd = [("content-type", "application/json")] if d.body else []
        fwd += sorted(self.policy.forward_headers.items())
        return self._record(method, host, path, fwd, d.body, "allow", "")

    def on_response(self, seq: int, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.wal.record_ingress(seq, status, headers, body)
