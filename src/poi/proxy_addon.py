"""mitmproxy addon (runs inside the poi-proxy container). Thin adapter over EgressGate."""
from __future__ import annotations

import os
from pathlib import Path

from mitmproxy import http

from poi import policy as pol
from poi.dnsstub import start_dns
from poi.fingerprint import FingerprintSet
from poi.gate import EgressGate
from poi.wal import WalWriter

RUN = Path(os.environ.get("POI_RUN", "/run/poi"))
SECRETS = Path(os.environ.get("POI_SECRETS", "/run/poi-secrets"))   # sealed mode: tmpfs, read-only


def _blocked(reason: str) -> http.Response:
    return http.Response.make(403, f"blocked by poi: {reason}\n".encode(), {"content-type": "text/plain"})


class PoiAddon:
    def __init__(self) -> None:
        self.policy = pol.load(RUN / "policy.yaml")
        sealer = None
        if (SECRETS / "ek").exists():
            from poi.seal.sealer import Sealer
            sealer = Sealer((SECRETS / "ek").read_bytes())
        self.wal = WalWriter(RUN / "proxy-wal", RUN / "evidence", sealer)
        fp = None
        if (RUN / "fingerprints.bin").exists():
            kp = SECRETS / "fingerprint.key" if (SECRETS / "fingerprint.key").exists() else RUN / "fingerprint.key"
            fp = FingerprintSet.load(RUN / "fingerprints.bin", kp.read_bytes(),
                                     self.policy.fingerprint_k, self.policy.fingerprint_w)
        # Kill switch: the operator creates <run>/isolate; from the next request on everything is blocked and logged.
        isolated = (RUN / "isolate").exists
        self.gate = EgressGate(self.policy, self.wal, fp, isolated=isolated)
        self.dns = start_dns(self.wal, self.policy.hosts, os.environ["POI_PROXY_IP"],
                             allow_all=self.policy.allow_all_egress, isolated=isolated)

    def http_connect(self, flow: http.HTTPFlow) -> None:
        r = self.gate.on_connect(flow.request.host)
        if r.verdict != "allow":
            flow.response = _blocked(r.reason)

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        host = req.pretty_host
        r = self.gate.on_request(host, req.method, req.path, list(req.headers.items(multi=True)),
                                 req.raw_content or b"")
        if r.verdict != "allow":
            flow.response = _blocked(r.reason)
            return
        flow.metadata["poi_seq"] = r.seq
        if self.policy.allow_all_egress:
            return                               # forwarded unchanged (already in the WAL)
        req.headers.clear()                      # drop every client header: no header side channel
        if req.http_version.startswith("HTTP/1"):
            req.headers["host"] = host
        for k, v in r.headers:
            req.headers[k] = v
        req.content = r.body                     # canonical JSON; sets content-length

    def response(self, flow: http.HTTPFlow) -> None:
        seq = flow.metadata.get("poi_seq")
        if seq is not None and flow.response is not None:
            self.gate.on_response(seq, flow.response.status_code,
                                  list(flow.response.headers.items(multi=True)), flow.response.raw_content or b"")


addons = [PoiAddon()]
