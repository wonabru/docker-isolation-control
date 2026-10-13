"""Content-addressed store for raw bytes (request/response bodies, config JSON)."""
from __future__ import annotations

import os
from pathlib import Path

from poi.canonical import b2b256


def put(evidence_dir: Path, data: bytes) -> str:
    digest = b2b256(data)
    path = Path(evidence_dir) / f"{digest}.bin"
    if not path.exists():
        tmp = path.with_suffix(f".tmp{os.getpid()}")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    return digest


def get(evidence_dir: Path, digest: str) -> bytes | None:
    """Return stored bytes, or None if missing or corrupted."""
    path = Path(evidence_dir) / f"{digest}.bin"
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    return data if b2b256(data) == digest else None
