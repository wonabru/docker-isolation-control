"""Shared builders for tests."""
from pathlib import Path

from poi import canonical as c
from poi.ledger import DeltaOp, Ledger
from poi.lthash import LtHash

T0 = "2026-10-13T18:00:00Z"


def egress(seq, verdict="allow", body_digest="b" * 64):
    return c.egress_element(seq, T0, "POST", "api.example.com", "/v1/score",
                            "h" * 64, body_digest, verdict, "" if verdict == "allow" else "schema")


def make_run(tmp_path: Path, key, n_egress=(2, 1)):
    """Build a small valid run: genesis with 2 files + config, then ticks with egress events."""
    led = Ledger(tmp_path, key)
    accs = {a: LtHash() for a in ("state", "egress", "ingress")}
    counts = {"egress": 0, "ingress": 0}
    f1 = c.file_element("/etc/a", "file", 0o644, 0, 0, "1" * 64)
    f2 = c.file_element("/etc/b", "file", 0o644, 0, 0, "2" * 64)
    cfg = c.config_element("c" * 64)
    ops = [DeltaOp("add", "state", e) for e in (f1, f2, cfg)]
    for op in ops:
        accs["state"].add(op.element)
    container = {"id": "abc", "image": "sha256:" + "0" * 64}
    led.append(t=T0, container=container, policy_digest="p" * 64, accs=accs, counts=counts, ops=ops)
    for i, n in enumerate(n_egress):
        ops = []
        f2new = c.file_element("/etc/b", "file", 0o644, 0, 0, str(i) * 64)
        ops += [DeltaOp("sub", "state", f2), DeltaOp("add", "state", f2new)]
        accs["state"].sub(f2).add(f2new)
        f2 = f2new
        for _ in range(n):
            counts["egress"] += 1
            e = egress(counts["egress"])
            ing = c.ingress_element(counts["egress"], 200, "h" * 64, "r" * 64)
            ops += [DeltaOp("add", "egress", e), DeltaOp("add", "ingress", ing)]
            accs["egress"].add(e)
            accs["ingress"].add(ing)
            counts["ingress"] += 1
        led.append(t=f"2026-10-13T18:00:0{i + 1}Z", container=container, policy_digest="p" * 64,
                   accs=accs, counts=counts, ops=ops)
    return led
