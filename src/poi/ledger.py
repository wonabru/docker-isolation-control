"""Append-only, signed chain of checkpoints with per-checkpoint delta files."""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from poi.canonical import b2b256, canonical_json, checkpoint_digest, checkpoint_signing_bytes
from poi.lthash import LtHash

ACCS = ("state", "egress", "ingress")


def pubkey_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def generate_key(path: Path) -> str:
    """Write a raw 32-byte Ed25519 private key (0600) and `<path>.pub` (hex). Returns pubkey hex."""
    path = Path(path)
    key = Ed25519PrivateKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes_raw())
    pub = pubkey_hex(key)
    path.with_name(path.name + ".pub").write_text(pub + "\n")
    return pub


def load_key(path: Path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(Path(path).read_bytes())


@dataclass
class DeltaOp:
    op: str        # "add" | "sub"
    acc: str       # "state" | "egress" | "ingress"
    element: bytes

    def to_json(self) -> dict:
        return {"op": self.op, "acc": self.acc, "element": base64.b64encode(self.element).decode("ascii")}

    @classmethod
    def from_json(cls, d: dict) -> "DeltaOp":
        return cls(d["op"], d["acc"], base64.b64decode(d["element"], validate=True))


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def delta_bytes(ops: list[DeltaOp]) -> bytes:
    return b"".join(canonical_json(op.to_json()) + b"\n" for op in ops)


class Ledger:
    def __init__(self, run_dir: Path, key: Ed25519PrivateKey) -> None:
        self.run_dir = Path(run_dir)
        self.key = key
        self.ledger_dir = self.run_dir / "ledger"
        self.delta_dir = self.run_dir / "delta"
        self.evidence_dir = self.run_dir / "evidence"
        for d in (self.ledger_dir, self.delta_dir, self.evidence_dir):
            d.mkdir(parents=True, exist_ok=True)
        pub = self.run_dir / "pubkey"
        if not pub.exists():
            pub.write_text(pubkey_hex(key) + "\n")

    def last(self) -> dict | None:
        files = sorted(self.ledger_dir.glob("*.json"))
        return json.loads(files[-1].read_bytes()) if files else None

    def read_delta(self, seq: int) -> list[DeltaOp]:
        lines = (self.delta_dir / f"{seq:06d}.jsonl").read_bytes().splitlines()
        return [DeltaOp.from_json(json.loads(line)) for line in lines if line]

    def append(self, *, t: str, container: dict, policy_digest: str,
               accs: dict[str, LtHash], counts: dict[str, int], ops: list[DeltaOp],
               restart: bool = False, rotate_to: Ed25519PrivateKey | None = None, final: bool = False) -> dict:
        """`final`: the operator signs that the run has ended — no checkpoint may follow this one."""
        prev = self.last()
        seq = 0 if prev is None else prev["seq"] + 1
        dbytes = delta_bytes(ops)
        _write_atomic(self.delta_dir / f"{seq:06d}.jsonl", dbytes)
        cp = {
            "v": 1,
            "seq": seq,
            "t": t,
            "prev": None if prev is None else checkpoint_digest(prev),
            "container": container,
            "policy": policy_digest,
            "state": {"vec": accs["state"].to_b64(), "digest": accs["state"].digest()},
            "egress": {"vec": accs["egress"].to_b64(), "digest": accs["egress"].digest(),
                       "count": counts["egress"]},
            "ingress": {"vec": accs["ingress"].to_b64(), "digest": accs["ingress"].digest(),
                        "count": counts["ingress"]},
            "delta": b2b256(dbytes),
            "restart": restart,
        }
        if rotate_to is not None:
            cp["rotate"] = pubkey_hex(rotate_to)
        if final:
            cp["final"] = True
        cp["sig"] = self.key.sign(checkpoint_signing_bytes(cp)).hex()
        _write_atomic(self.ledger_dir / f"{seq:06d}.json", canonical_json(cp))
        if rotate_to is not None:
            self.key = rotate_to
        return cp
