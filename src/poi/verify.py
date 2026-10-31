"""Independent verifier. Must import only: lthash, canonical, evidence, policy, seal (+ cryptography).

Replays the checkpoint chain from genesis and checks every claim a checkpoint makes.
"""
from __future__ import annotations

import base64
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from poi import canonical as c
from poi import evidence
from poi.lthash import LtHash
from poi.policy import Policy, config_violations
from poi.seal import FIELD_PREFIX, SealError

E_SIGNATURE = 10
E_CHAIN = 11
E_DELTA = 12
E_SEQ = 13
E_SCHEMA = 14
E_CONFIG = 15
E_EVIDENCE = 16
E_LIVE = 17
E_SEALED = 18

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
    sealed_unchecked: int = 0

    @property
    def finished(self) -> bool:
        """The operator signed the last checkpoint as the end of the run."""
        return bool(self.checkpoints and self.checkpoints[-1].get("final"))

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


def parse_delta(cp: dict, raw: bytes) -> list[tuple[str, str, bytes]]:
    """Check the delta file against its checkpoint and decode it into (op, acc, element)."""
    seq = cp["seq"]
    if c.b2b256(raw) != cp["delta"]:
        raise VerifyError(E_DELTA, seq, "delta file digest mismatch")
    ops = []
    for line in raw.splitlines():
        d = json.loads(line)
        if d["op"] not in ("add", "sub") or d["acc"] not in ACCS:
            raise VerifyError(E_DELTA, seq, f"malformed op {d}")
        ops.append((d["op"], d["acc"], base64.b64decode(d["element"], validate=True)))
    return ops


def _read_delta(run_dir: Path, cp: dict) -> bytes:
    try:
        return (run_dir / "delta" / f"{cp['seq']:06d}.jsonl").read_bytes()
    except FileNotFoundError:
        raise VerifyError(E_DELTA, cp["seq"], "delta file missing")


GetEvidence = Callable[[str], "bytes | None"]


def _evidence(get: GetEvidence, digest: str, cp_seq: int, what: str) -> bytes:
    data = get(digest)
    if data is None:
        raise VerifyError(E_EVIDENCE, cp_seq, f"{what} evidence {digest[:12]}… missing or corrupt")
    return data


def _check_binding(cp: dict, policy: Policy) -> None:
    if cp["policy"] != policy.digest:
        raise VerifyError(E_CONFIG, cp["seq"], "checkpoint is bound to a different policy")


def _check_config(seq: int, digest: str, get: GetEvidence, policy: Policy) -> None:
    doc = json.loads(_evidence(get, digest, seq, "config"))
    if v := config_violations(doc, policy):
        raise VerifyError(E_CONFIG, seq, "; ".join(v))


def _opened(get: GetEvidence, sealer, seq: int) -> GetEvidence:
    def g(digest: str) -> bytes | None:
        data = get(digest)
        if data is None:
            return None
        try:
            return sealer.open_evidence(data)
        except SealError as e:
            raise VerifyError(E_SEALED, seq, f"evidence {digest[:12]}…: {e}")
    return g


def _check_egress(ev: Event, get: GetEvidence, policy: Policy, sealer=None) -> bool:
    """Check one egress/dns event. Returns False when it is sealed and no client key was given:
    then only evidence integrity (16) is checked, not schema conformance (14)."""
    f = ev.fields
    if sealer is not None:
        try:
            f = sealer.open_fields(f)
        except SealError as e:
            raise VerifyError(E_SEALED, ev.checkpoint, f"{ev.domain} seq {ev.seq}: {e}")
        get = _opened(get, sealer, ev.checkpoint)
    elif any(x.startswith(FIELD_PREFIX) for x in f):
        if ev.domain == "egress":
            _evidence(get, f[6], ev.checkpoint, f"egress {ev.seq} headers")
            _evidence(get, f[7], ev.checkpoint, f"egress {ev.seq} body")
        return False
    if ev.domain == "dns":
        _, _, _, name, qtype, verdict = f
        if verdict == "allow" and ((name not in policy.hosts and not policy.allow_all_egress) or qtype != "A"):
            raise VerifyError(E_SCHEMA, ev.checkpoint, f"dns seq {ev.seq}: {name} answered but not allowed")
        return True
    _, _, _, method, host, path, hdig, bdig, verdict, _ = f
    headers = _evidence(get, hdig, ev.checkpoint, f"egress {ev.seq} headers")
    body = _evidence(get, bdig, ev.checkpoint, f"egress {ev.seq} body")
    if verdict != "allow" or policy.allow_all_egress:
        return True
    d = policy.decide(host, method, path, body)
    if d.verdict != "allow" or d.body != body:
        raise VerifyError(E_SCHEMA, ev.checkpoint, f"egress seq {ev.seq} does not satisfy policy ({d.reason})")
    fwd = [["content-type", "application/json"]] if body else []
    fwd += [[k, v] for k, v in sorted(policy.forward_headers.items())]
    if json.loads(headers) != sorted(fwd):
        raise VerifyError(E_SCHEMA, ev.checkpoint, f"egress seq {ev.seq} forwarded unexpected headers")
    return True


def _check_ingress(ev: Event, get: GetEvidence) -> None:
    _evidence(get, ev.fields[3], ev.checkpoint, f"ingress {ev.seq} headers")
    _evidence(get, ev.fields[4], ev.checkpoint, f"ingress {ev.seq} body")


class ChainVerifier:
    """Incremental verifier: feed checkpoints in order; state carries over between calls.

    Without a policy it checks 10–13 (chain); with a policy also 14–16 for each checkpoint.
    """

    def __init__(self, pubkey_hex: str, policy: Policy | None = None, sealer=None) -> None:
        self.pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        self.policy = policy
        self.sealer = sealer
        self.res = VerifyResult(accs={a: LtHash() for a in ACCS})
        self._allowed: set[int] = set()
        self._seen_ingress: set[int] = set()
        self._next_seq = 1
        self._prev: dict | None = None

    @property
    def next_checkpoint(self) -> int:
        return len(self.res.checkpoints)

    def feed(self, cp: dict, delta_raw: bytes, get_evidence: GetEvidence | None = None) -> list[Event]:
        """Verify one checkpoint. Returns the egress/dns/ingress events it introduced."""
        res = self.res
        seq = cp.get("seq")
        if seq != self.next_checkpoint:
            raise VerifyError(E_CHAIN, seq, f"expected checkpoint {self.next_checkpoint}")
        _check_sig(cp, self.pub)
        prev = self._prev
        if prev is None:
            if cp["prev"] is not None:
                raise VerifyError(E_CHAIN, seq, "genesis has non-null prev")
        else:
            if prev.get("final"):
                raise VerifyError(E_CHAIN, seq, "checkpoint after the final one")
            if cp["prev"] != c.checkpoint_digest(prev):
                raise VerifyError(E_CHAIN, seq, "prev does not match previous checkpoint")
            if cp["t"] < prev["t"]:
                raise VerifyError(E_CHAIN, seq, "time went backwards")

        accs = {a: h.copy() for a, h in res.accs.items()}   # commit only if the whole checkpoint verifies
        state = res.state_elements.copy()
        new_events: list[Event] = []
        new_configs: list[tuple[int, str]] = []
        next_seq = self._next_seq
        allowed, seen = set(self._allowed), set(self._seen_ingress)
        for op, acc, element in parse_delta(cp, delta_raw):
            fields = c.decode(element)
            if acc == "state":
                if fields[0] not in ("file", "config"):
                    raise VerifyError(E_DELTA, seq, f"domain {fields[0]} in state accumulator")
                if op == "add":
                    accs["state"].add(element)
                    state[element] += 1
                    if fields[0] == "config":
                        new_configs.append((seq, fields[1]))
                else:
                    if state[element] == 0:
                        raise VerifyError(E_DELTA, seq, "sub of element not in state")
                    accs["state"].sub(element)
                    state[element] -= 1
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
                    allowed.add(ev.seq)
            else:
                if ev.domain != "ingress":
                    raise VerifyError(E_DELTA, seq, f"domain {ev.domain} in ingress accumulator")
                if ev.seq not in allowed or ev.seq in seen:
                    raise VerifyError(E_SEQ, seq, f"ingress seq {ev.seq} has no unique allowed request")
                seen.add(ev.seq)
            accs[acc].add(element)
            new_events.append(ev)

        for acc in ACCS:
            claimed = LtHash.from_b64(cp[acc]["vec"])
            if claimed != accs[acc] or cp[acc]["digest"] != claimed.digest():
                raise VerifyError(E_DELTA, seq, f"{acc} accumulator does not match prev + delta")
        n_egress = len(res.egress) + sum(e.domain != "ingress" for e in new_events)
        n_ingress = len(res.ingress) + sum(e.domain == "ingress" for e in new_events)
        if cp["egress"]["count"] != n_egress or cp["ingress"]["count"] != n_ingress:
            raise VerifyError(E_SEQ, seq, "count does not match number of events")

        unchecked = 0
        if self.policy is not None:
            get = get_evidence or (lambda d: None)
            _check_binding(cp, self.policy)
            for cseq, digest in new_configs:
                _check_config(cseq, digest, get, self.policy)
            for ev in new_events:
                if ev.domain == "ingress":
                    _check_ingress(ev, get)
                elif not _check_egress(ev, get, self.policy, self.sealer):
                    unchecked += 1

        res.accs, res.state_elements = accs, state
        res.sealed_unchecked += unchecked
        res.config_digests += new_configs
        for ev in new_events:
            (res.ingress if ev.domain == "ingress" else res.egress).append(ev)
        self._next_seq, self._allowed, self._seen_ingress = next_seq, allowed, seen
        if "rotate" in cp:
            self.pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cp["rotate"]))
        res.checkpoints.append(cp)
        self._prev = cp
        return new_events


def verify_chain(run_dir: Path, pubkey_hex: str) -> VerifyResult:
    """Checks signatures (10), chain links and time (11), delta sums (12), seq/count (13)."""
    run_dir = Path(run_dir)
    v = ChainVerifier(pubkey_hex)
    for cp in _load_checkpoints(run_dir):
        v.feed(cp, _read_delta(run_dir, cp))
    return v.res


def verify_policy(res: VerifyResult, run_dir: Path, policy: Policy, sealer=None) -> None:
    """Checks policy binding and configuration (15), evidence (16) and schema conformance (14)."""
    edir = Path(run_dir) / "evidence"

    def get(d: str) -> bytes | None:
        return evidence.get(edir, d)

    for cp in res.checkpoints:
        _check_binding(cp, policy)
    for seq, digest in res.config_digests:
        _check_config(seq, digest, get, policy)
    res.sealed_unchecked = 0
    for ev in res.egress:
        if not _check_egress(ev, get, policy, sealer):
            res.sealed_unchecked += 1
    for ev in res.ingress:
        _check_ingress(ev, get)


def verify_run(run_dir: Path, pubkey_hex: str, policy: Policy, sealer=None) -> ChainVerifier:
    """Incremental equivalent of verify_chain + verify_policy over a run directory."""
    run_dir = Path(run_dir)
    v = ChainVerifier(pubkey_hex, policy, sealer)
    for cp in _load_checkpoints(run_dir):
        v.feed(cp, _read_delta(run_dir, cp), lambda d: evidence.get(run_dir / "evidence", d))
    return v
