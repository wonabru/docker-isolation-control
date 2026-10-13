"""User-facing summary of a verified run: blocked attempts, fingerprint hits, channel capacity."""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from poi import evidence
from poi.fingerprint import FingerprintSet
from poi.policy import Policy, endpoint_capacity
from poi.verify import VerifyResult


def build_report(res: VerifyResult, run_dir: Path, policy: Policy,
                 fingerprints: FingerprintSet | None = None) -> dict:
    run_dir = Path(run_dir)
    allowed: Counter = Counter()
    blocked: list[dict] = []
    dns: Counter = Counter()
    hits: list[dict] = []
    for ev in res.egress:
        f = ev.fields
        if ev.domain == "dns":
            dns[f[5]] += 1
            if f[5] == "block":
                blocked.append({"seq": ev.seq, "t": f[2], "kind": "dns", "target": f[3], "reason": "dns"})
            if fingerprints is not None and fingerprints.scan(f[3].encode()):
                hits.append({"seq": ev.seq, "verdict": f[5], "sources": sorted(fingerprints.scan(f[3].encode()))})
            continue
        _, _, t, method, host, path, _, bdig, verdict, reason = f
        if verdict == "allow":
            allowed[(host, method, path)] += 1
        else:
            blocked.append({"seq": ev.seq, "t": t, "kind": "http", "target": f"{method} {host}{path}",
                            "reason": reason})
        if fingerprints is not None:
            body = evidence.get(run_dir / "evidence", bdig) or b""
            if found := fingerprints.scan(body + b" " + path.encode()):
                hits.append({"seq": ev.seq, "verdict": verdict, "sources": sorted(found)})
    capacity = 0.0
    per_endpoint = []
    for (host, method, path), n in sorted(allowed.items()):
        ep = policy.find(host, method, path)
        bits = endpoint_capacity(ep)
        capacity += bits * n
        per_endpoint.append({"endpoint": f"{method} {host}{path}", "requests": n, "bits_per_request": bits})
    leaked_allowed = [h for h in hits if h["verdict"] == "allow"]
    return {
        "checkpoints": len(res.checkpoints),
        "last_checkpoint": res.last["seq"],
        "state_digest": res.last["state"]["digest"],
        "egress_events": len(res.egress),
        "allowed_requests": sum(allowed.values()),
        "endpoints": per_endpoint,
        "blocked": blocked,
        "blocked_by_reason": dict(Counter(b["reason"] for b in blocked)),
        "dns": dict(dns),
        "capacity_bits_upper_bound": capacity,
        "fingerprints_checked": fingerprints is not None,
        "fingerprint_hits": hits,
        "fingerprint_hits_in_allowed_traffic": len(leaked_allowed),
    }


def render_text(r: dict) -> str:
    cap = r["capacity_bits_upper_bound"]
    lines = [
        f"Checkpoints verified: {r['checkpoints']} (last #{r['last_checkpoint']}, state {r['state_digest'][:16]}…)",
        f"Egress events: {r['egress_events']}  allowed requests: {r['allowed_requests']}  "
        f"blocked: {len(r['blocked'])} {r['blocked_by_reason']}",
        f"DNS queries: {r['dns']}",
        "Covert-channel upper bound in allowed traffic: "
        + ("UNBOUNDED (schema allows free-form values)" if math.isinf(cap) else f"{cap:.0f} bits"),
    ]
    for e in r["endpoints"]:
        lines.append(f"  {e['endpoint']}: {e['requests']} × {e['bits_per_request']:.1f} bits")
    if r["fingerprints_checked"]:
        lines.append(f"User-data fingerprint hits in ALLOWED traffic: {r['fingerprint_hits_in_allowed_traffic']}")
        lines.append(f"User-data fingerprint hits in blocked attempts: "
                     f"{len(r['fingerprint_hits']) - r['fingerprint_hits_in_allowed_traffic']}")
    for b in r["blocked"]:
        lines.append(f"  blocked #{b['seq']} {b['t']} {b['target']} ({b['reason']})")
    lines.append("Not covered: timing/request-count channels beyond the bound above, kernel escapes, "
                 "host compromise (see spec §9).")
    return "\n".join(lines)
