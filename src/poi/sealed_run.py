"""Sealed run lifecycle (spec §6): run key → client grant → tmpfs workspace → EK → sealed output → wipe."""
from __future__ import annotations

import json
import logging
import os
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from poi import canonical as c
from poi.seal import SealError, bundle
from poi.seal import sealer as sl
from poi.seal.grant import FP_LABEL, RunKey, bundle_label, wait_for_grant

log = logging.getLogger("poi")
SHM = Path("/dev/shm")
_ZERO = bytes(1 << 20)


def swap_active(proc_swaps: Path = Path("/proc/swaps")) -> bool:
    try:
        return len(proc_swaps.read_text().strip().splitlines()) > 1
    except FileNotFoundError:
        return False


@dataclass
class SealedOptions:
    client_pub: bytes
    mounts: dict[str, str]                       # sealed bundle path -> container target
    tmpfs: list[str] = field(default_factory=lambda: ["/tmp"])
    allow_swap: bool = False
    grant_timeout: float = 600.0


def _write_secret(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def wipe_dir(path: Path, root_rm: Callable[[Path], None] | None = None) -> None:
    """Overwrite regular files with zeros (best effort), then remove the tree; root_rm handles root-owned leftovers."""
    path = Path(path)
    if not path.exists():
        return
    for root, _, files in os.walk(path):
        for name in files:
            p = Path(root) / name
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                left = p.stat().st_size
                with open(p, "r+b") as f:
                    while left > 0:
                        left -= f.write(_ZERO[:min(left, len(_ZERO))])
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)
    if path.exists() and root_rm is not None:
        root_rm(path)
        shutil.rmtree(path, ignore_errors=True)


def run_id_of(run_dir: Path) -> str | None:
    """Run id from run.pub (written first) or runtime.json."""
    for name in ("run.pub", "runtime.json"):
        try:
            return json.loads((Path(run_dir) / name).read_text())["run_id"]
        except (FileNotFoundError, ValueError, KeyError):
            continue
    return None


class SealedSession:
    def __init__(self, run_dir: Path, opts: SealedOptions, run_id: str | None = None,
                 shm_root: Path = SHM, swap: bool | None = None) -> None:
        self.run_dir = Path(run_dir).resolve()
        self.opts = opts
        self.run_id = run_id or uuid.uuid4().hex[:8]
        self.tmp = Path(shm_root) / f"poi-{self.run_id}"
        self.secrets, self.out = self.tmp / "secrets", self.tmp / "out"
        self.swap = swap_active() if swap is None else swap
        self.ro_mounts: dict[str, str] = {}
        self.bundle_digests: dict[str, str] = {}
        self.run_pub_raw = b""
        self.sealer: sl.Sealer | None = None

    def check_swap(self) -> None:
        if self.swap and not self.opts.allow_swap:
            raise SealError("swap is active, so decrypted data could reach disk (--allow-swap to accept)")

    def setup(self, want_fingerprint_key: bool) -> None:
        """Publish run.pub, wait for the client's grant, decrypt bundles into tmpfs, create EK."""
        self.check_swap()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.tmp.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.tmp, 0o700)
        for d in (self.secrets, self.tmp / "data"):
            d.mkdir(mode=0o700, exist_ok=True)
        self.out.mkdir(exist_ok=True)
        os.chmod(self.out, 0o777)            # any workload uid may write; the 0700 parent keeps others out
        rk = RunKey.generate(self.run_id)
        self.run_pub_raw = rk.pub_bytes()
        (self.run_dir / "run.pub").write_bytes(self.run_pub_raw)
        labels = {}
        for path, target in self.opts.mounts.items():
            self.bundle_digests[target] = bundle.file_digest(Path(path))
            labels[path] = bundle_label(self.bundle_digests[target])
        needed = set(labels.values()) | ({FP_LABEL} if want_fingerprint_key else set())
        log.info("sealed run %s: send %s to the data owner and put their grant at %s",
                 self.run_id, self.run_dir / "run.pub", self.run_dir / "grant.bin")
        keys = wait_for_grant(self.run_dir / "grant.bin", rk, needed, self.opts.grant_timeout)
        del rk                               # the run private key is gone: the grant is useless from now on
        for n, (path, target) in enumerate(self.opts.mounts.items()):
            dest = self.tmp / "data" / str(n)
            bundle.unseal_to(Path(path), keys[labels[path]], dest)
            self.ro_mounts[str(dest)] = target
        if want_fingerprint_key:
            _write_secret(self.secrets / "fingerprint.key", keys[FP_LABEL])
        ek = sl.new_ek()
        _write_secret(self.secrets / "ek", ek)
        (self.run_dir / "sealed.json").write_bytes(
            sl.sealed_doc(ek, self.opts.client_pub, self.run_id, self.run_pub_raw))
        self.sealer = sl.Sealer(ek)

    def config_info(self, out_target: str | None) -> dict:
        return {"client_pub": c.b2b256(self.opts.client_pub), "run_pub": c.b2b256(self.run_pub_raw),
                "mounts": dict(sorted(self.bundle_digests.items())), "swap": self.swap, "out_target": out_target}

    def finish(self) -> Path | None:
        """Seal the output directory to the client as run/out.sealed (nothing if it is empty)."""
        if not self.out.exists() or not any(self.out.iterdir()):
            return None
        out = self.run_dir / "out.sealed"
        bundle.seal_dir(self.out, out, self.opts.client_pub, kind="out")
        return out

    def wipe(self, root_rm: Callable[[Path], None] | None = None) -> None:
        wipe_dir(self.tmp, root_rm)
        self.sealer = None
