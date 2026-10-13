"""Where checkpoints go after they are written. v1: local; later Rekor / HTTP."""
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from poi.canonical import canonical_json, checkpoint_digest


class Publisher(Protocol):
    def publish(self, checkpoint: dict) -> None: ...


class LocalPublisher:
    """Appends {seq, t, digest} of every checkpoint to `heads.jsonl` (the hand-off point for exporters)."""

    def __init__(self, run_dir: Path) -> None:
        self.path = Path(run_dir) / "heads.jsonl"

    def publish(self, checkpoint: dict) -> None:
        line = canonical_json({"seq": checkpoint["seq"], "t": checkpoint["t"],
                               "digest": checkpoint_digest(checkpoint)})
        with open(self.path, "ab") as f:
            f.write(line + b"\n")
