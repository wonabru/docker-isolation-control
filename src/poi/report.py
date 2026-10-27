"""User-facing summary of a verified run: blocked attempts, fingerprint hits, channel capacity."""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from poi import evidence
from poi.fingerprint import FingerprintSet
from poi.policy import Policy, endpoint_capacity
from poi.seal.sealer import LOCKED, display_fields, is_sealed
from poi.verify import VerifyResult


def build_report(res: VerifyResult, run_dir: Path, policy: Policy,
                 fingerprints: FingerprintSet | None = None, sealer=None) -> dict:
    """Without `sealer`, fields of a sealed run show as 🔒 and are not fingerprint-scanned."""
    run_dir = Path(run_dir)
    allowed: Counter = Counter()
    blocked: list[dict] = []
    dns: Counter = Counter()
    hits: list[dict] = []
    locked = 0
    for ev in res.egress:
        is_locked = sealer is None and any(is_sealed(x) for x in ev.fields)
        locked += is_locked
        f = sealer.open_fields(ev.fields) if sealer is not None else display_fields(ev.fields)
        scan = fingerprints is not None and not is_locked
        if ev.domain == "dns":
            dns[f[5]] += 1
            if f[5] == "block":
                blocked.append({"seq": ev.seq, "t": f[2], "kind": "dns", "target": f[3], "reason": "dns"})
            if scan and (found := fingerprints.scan(f[3].encode())):
                hits.append({"seq": ev.seq, "verdict": f[5], "sources": sorted(found)})
            continue
        _, _, t, method, host, path, _, bdig, verdict, reason = f
        if verdict == "allow":
            allowed[(host, method, path)] += 1
        else:
            blocked.append({"seq": ev.seq, "t": t, "kind": "http", "target": f"{method} {host}{path}",
                            "reason": reason})
        if scan:
            body = evidence.get(run_dir / "evidence", bdig) or b""
            if sealer is not None:
                body = sealer.open_evidence(body)
            if found := fingerprints.scan(body + b" " + path.encode()):
                hits.append({"seq": ev.seq, "verdict": verdict, "sources": sorted(found)})
    capacity = 0.0
    per_endpoint = []
    for (host, method, path), n in sorted(allowed.items()):
        ep = policy.find(host, method, path)
        bits = endpoint_capacity(ep) if ep else math.inf        # 🔒: endpoint unknown without the key
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
        "sealed_locked": locked,
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
    if r.get("sealed_locked"):
        lines.append(f"Sealed events shown as {LOCKED}: {r['sealed_locked']} (use --client-key to read them)")
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
