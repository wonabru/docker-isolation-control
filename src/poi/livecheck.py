"""`poi verify --live`: recompute the container state hash from Docker and compare."""
from __future__ import annotations

from pathlib import Path

import docker

from poi import policy as pol
from poi.lthash import LtHash
from poi.runtime import RuntimeInfo
from poi.state import DockerContainerFS, StateTracker


def live_state(run_dir: Path, client=None) -> LtHash:
    client = client or docker.from_env()
    run_dir = Path(run_dir).resolve()
    info = RuntimeInfo.load(run_dir)
    policy = pol.load(run_dir / "policy.yaml")
    output = (run_dir / "out", policy.output_volume) if policy.output_volume else None
    fs = DockerContainerFS(client, client.containers.get(info.workload_id))
    return LtHash.of(StateTracker(fs, output).target(full=True).values())
