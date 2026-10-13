"""Independent verifier. Must import only: lthash, canonical, evidence, policy (+ cryptography).

Replays the checkpoint chain from genesis and checks every claim a checkpoint makes.
"""
from __future__ import annotations

import base64
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from poi import canonical as c
from poi import evidence
from poi.lthash import LtHash
from poi.policy import Policy, config_violations

E_SIGNATURE = 10
E_CHAIN = 11
E_DELTA = 12
E_SEQ = 13
E_SCHEMA = 14
E_CONFIG = 15
E_EVIDENCE = 16
E_LIVE = 17

ACCS = ("state", "egress", "ingress")


class VerifyError(Exception):
    def __init__(self, code: int, seq: int | None, msg: str) -> None:
        super().__init__(f"[{code}] checkpoint {seq}: {msg}")
        self.code = code
        self.seq = seq
        self.msg = msg


@dataclass
class Event:
    """A decoded egress/dns/ingress element plus the checkpoint it was recorded in."""
    checkpoint: int
    fields: list[str]

    @property
    def domain(self) -> str:
        return self.fields[0]

    @property
    def seq(self) -> int:
        return int(self.fields[1])


@dataclass
class VerifyResult:
    checkpoints: list[dict] = field(default_factory=list)
    accs: dict[str, LtHash] = field(default_factory=dict)
    state_elements: Counter = field(default_factory=Counter)
    egress: list[Event] = field(default_factory=list)
    ingress: list[Event] = field(default_factory=list)
    config_digests: list[tuple[int, str]] = field(default_factory=list)

    @property
    def last(self) -> dict:
        return self.checkpoints[-1]


def _load_checkpoints(run_dir: Path) -> list[dict]:
    files = sorted((run_dir / "ledger").glob("*.json"))
    if not files:
        raise VerifyError(E_CHAIN, None, "no checkpoints")
    cps = []
    for i, f in enumerate(files):
        if f.name != f"{i:06d}.json":
            raise VerifyError(E_CHAIN, i, f"missing or misnamed checkpoint file (found {f.name})")
        cp = json.loads(f.read_bytes())
        if cp.get("seq") != i:
            raise VerifyError(E_CHAIN, i, f"seq field {cp.get('seq')} != position {i}")
        cps.append(cp)
    return cps


def _check_sig(cp: dict, pub: Ed25519PublicKey) -> None:
    try:
        pub.verify(bytes.fromhex(cp["sig"]), c.checkpoint_signing_bytes(cp))
    except (InvalidSignature, ValueError, KeyError) as e:
        raise VerifyError(E_SIGNATURE, cp.get("seq"), f"bad signature ({type(e).__name__})")


def _read_delta(run_dir: Path, cp: dict) -> list[tuple[str, str, bytes]]:
    seq = cp["seq"]
    try:
        raw = (run_dir / "delta" / f"{seq:06d}.jsonl").read_bytes()
    except FileNotFoundError:
        raise VerifyError(E_DELTA, seq, "delta file missing")
    if c.b2b256(raw) != cp["delta"]:
        raise VerifyError(E_DELTA, seq, "delta file digest mismatch")
    ops = []
    for line in raw.splitlines():
        d = json.loads(line)
        if d["op"] not in ("add", "sub") or d["acc"] not in ACCS:
            raise VerifyError(E_DELTA, seq, f"malformed op {d}")
        ops.append((d["op"], d["acc"], base64.b64decode(d["element"], validate=True)))
    return ops


def verify_chain(run_dir: Path, pubkey_hex: str) -> VerifyResult:
    """Checks signatures (10), chain links and time (11), delta sums (12), seq/count (13)."""
    run_dir = Path(run_dir)
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
    res = VerifyResult(accs={a: LtHash() for a in ACCS})
    allowed_seqs: set[int] = set()
    seen_ingress: set[int] = set()
    next_seq = 1
    prev: dict | None = None

    for cp in _load_checkpoints(run_dir):
        seq = cp["seq"]
        _check_sig(cp, pub)
        if prev is None:
            if cp["prev"] is not None:
                raise VerifyError(E_CHAIN, seq, "genesis has non-null prev")
        else:
            if cp["prev"] != c.checkpoint_digest(prev):
                raise VerifyError(E_CHAIN, seq, "prev does not match previous checkpoint")
            if cp["t"] < prev["t"]:
                raise VerifyError(E_CHAIN, seq, "time went backwards")

        for op, acc, element in _read_delta(run_dir, cp):
            fields = c.decode(element)
            if acc == "state":
                if fields[0] not in ("file", "config"):
                    raise VerifyError(E_DELTA, seq, f"domain {fields[0]} in state accumulator")
                if op == "add":
                    res.accs["state"].add(element)
                    res.state_elements[element] += 1
                    if fields[0] == "config":
                        res.config_digests.append((seq, fields[1]))
                else:
                    if res.state_elements[element] == 0:
                        raise VerifyError(E_DELTA, seq, "sub of element not in state")
                    res.accs["state"].sub(element)
                    res.state_elements[element] -= 1
                continue
            if op != "add":
                raise VerifyError(E_SEQ, seq, f"{acc} accumulator is append-only")
            ev = Event(seq, fields)
            if acc == "egress":
                if ev.domain not in ("egress", "dns"):
                    raise VerifyError(E_DELTA, seq, f"domain {ev.domain} in egress accumulator")
                if ev.seq != next_seq:
                    raise VerifyError(E_SEQ, seq, f"egress seq {ev.seq}, expected {next_seq}")
                next_seq += 1
                if ev.domain == "egress" and fields[8] == "allow":
                    allowed_seqs.add(ev.seq)
                res.accs["egress"].add(element)
                res.egress.append(ev)
            else:
                if ev.domain != "ingress":
                    raise VerifyError(E_DELTA, seq, f"domain {ev.domain} in ingress accumulator")
                if ev.seq not in allowed_seqs or ev.seq in seen_ingress:
                    raise VerifyError(E_SEQ, seq, f"ingress seq {ev.seq} has no unique allowed request")
                seen_ingress.add(ev.seq)
                res.accs["ingress"].add(element)
                res.ingress.append(ev)

        for acc in ACCS:
            claimed = LtHash.from_b64(cp[acc]["vec"])
            if claimed != res.accs[acc] or cp[acc]["digest"] != claimed.digest():
                raise VerifyError(E_DELTA, seq, f"{acc} accumulator does not match prev + delta")
        if cp["egress"]["count"] != len(res.egress) or cp["ingress"]["count"] != len(res.ingress):
            raise VerifyError(E_SEQ, seq, "count does not match number of events")

        if "rotate" in cp:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cp["rotate"]))
        res.checkpoints.append(cp)
        prev = cp
    return res



def _evidence(run_dir: Path, digest: str, cp_seq: int, what: str) -> bytes:
    data = evidence.get(run_dir / "evidence", digest)
    if data is None:
        raise VerifyError(E_EVIDENCE, cp_seq, f"{what} evidence {digest[:12]}… missing or corrupt")
    return data


def verify_policy(res: VerifyResult, run_dir: Path, policy: Policy) -> None:
    """Checks policy binding and configuration (15), evidence (16) and schema conformance (14)."""
    run_dir = Path(run_dir)
    for cp in res.checkpoints:
        if cp["policy"] != policy.digest:
            raise VerifyError(E_CONFIG, cp["seq"], "checkpoint is bound to a different policy")
    for seq, digest in res.config_digests:
        doc = json.loads(_evidence(run_dir, digest, seq, "config"))
        if v := config_violations(doc, policy):
            raise VerifyError(E_CONFIG, seq, "; ".join(v))
    for ev in res.egress:
        f = ev.fields
        if ev.domain == "dns":
            _, _, _, name, qtype, verdict = f
            if verdict == "allow" and (name not in policy.hosts or qtype != "A"):
                raise VerifyError(E_SCHEMA, ev.checkpoint, f"dns seq {ev.seq}: {name} answered but not allowed")
            continue
        _, _, _, method, host, path, hdig, bdig, verdict, _ = f
        headers = _evidence(run_dir, hdig, ev.checkpoint, f"egress {ev.seq} headers")
        body = _evidence(run_dir, bdig, ev.checkpoint, f"egress {ev.seq} body")
        if verdict != "allow":
            continue
        d = policy.decide(host, method, path, body)
        if d.verdict != "allow" or d.body != body:
            raise VerifyError(E_SCHEMA, ev.checkpoint, f"egress seq {ev.seq} does not satisfy policy ({d.reason})")
        fwd = [["content-type", "application/json"]] if body else []
        fwd += [[k, v] for k, v in sorted(policy.forward_headers.items())]
        if json.loads(headers) != sorted(fwd):
            raise VerifyError(E_SCHEMA, ev.checkpoint, f"egress seq {ev.seq} forwarded unexpected headers")
    for ev in res.ingress:
        _evidence(run_dir, ev.fields[3], ev.checkpoint, f"ingress {ev.seq} headers")
        _evidence(run_dir, ev.fields[4], ev.checkpoint, f"ingress {ev.seq} body")
