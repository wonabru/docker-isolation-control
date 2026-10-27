"""Run key and grant (spec §5.6): the client wraps data keys to a key that exists only in RAM during the run."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from poi import canonical as c
from poi.seal import SealError, b64d, b64e, kem

log = logging.getLogger("poi")
FP_LABEL = "fingerprint-key"


def bundle_label(digest: str) -> str:
    return f"bundle:{digest}"


def _aad(run_id: str, label: str) -> bytes:
    return f"poi-grant\0{run_id}\0{label}".encode()


@dataclass
class RunKey:
    run_id: str
    sk: bytes
    pk: bytes

    @classmethod
    def generate(cls, run_id: str) -> "RunKey":
        sk, pk = kem.generate()
        return cls(run_id, sk, pk)

    def pub_bytes(self) -> bytes:
        return c.canonical_json({"run_id": self.run_id, "pub": self.pk.hex()}) + b"\n"


def read_run_pub(raw: bytes) -> tuple[str, bytes]:
    try:
        d = json.loads(raw)
        return d["run_id"], bytes.fromhex(d["pub"])
    except (ValueError, KeyError, TypeError) as e:
        raise SealError(f"malformed run.pub: {e}") from e


def make_grant(run_pub_raw: bytes, keys: dict[str, bytes]) -> bytes:
    run_id, pk = read_run_pub(run_pub_raw)
    wrapped = {label: b64e(kem.wrap(pk, key, _aad(run_id, label))) for label, key in sorted(keys.items())}
    return c.canonical_json({"v": 1, "run_id": run_id, "keys": wrapped}) + b"\n"


def open_grant(raw: bytes, rk: RunKey) -> dict[str, bytes]:
    try:
        d = json.loads(raw)
        run_id, items = d["run_id"], dict(d["keys"])
    except (ValueError, KeyError, TypeError) as e:
        raise SealError(f"malformed grant: {e}") from e
    if run_id != rk.run_id:
        raise SealError(f"grant is for run {run_id}, this is run {rk.run_id}")
    try:
        return {label: kem.unwrap(rk.sk, b64d(v), _aad(run_id, label)) for label, v in items.items()}
    except (ValueError, TypeError) as e:
        raise SealError(f"malformed grant: {e}") from e


def wait_for_grant(path: Path, rk: RunKey, needed: set[str], timeout: float, poll: float = 0.5, *,
                   sleep: Callable[[float], None] = time.sleep,
                   monotonic: Callable[[], float] = time.monotonic) -> dict[str, bytes]:
    """Poll `path` until a grant that opens and holds every `needed` key appears. Bad grants are skipped."""
    deadline = monotonic() + timeout
    rejected: set[str] = set()
    while True:
        try:
            raw = Path(path).read_bytes()
        except FileNotFoundError:
            raw = None
        if raw is not None and (d := c.b2b256(raw)) not in rejected:
            try:
                keys = open_grant(raw, rk)
                missing = needed - keys.keys()
                if not missing:
                    return keys
                log.warning("grant rejected: no key for %s", sorted(missing))
            except SealError as e:
                log.warning("grant rejected: %s", e)
            rejected.add(d)
        if monotonic() >= deadline:
            raise SealError(f"no valid grant in {path} within {timeout:g} s")
        sleep(poll)
