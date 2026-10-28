"""`poi run` / `poi resume`: wire runtime + state + WAL + ledger into the tick loop."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

import docker

from poi import policy as pol
from poi.engine import Engine
from poi.ledger import Ledger, load_key
from poi.publish import LocalPublisher
from poi.runtime import Runtime, RuntimeInfo, ensure_proxy_image, root_rm
from poi.seal import SealError
from poi.sealed_run import SealedOptions, SealedSession
from poi.state import DockerContainerFS, StateTracker
from poi.wal import WalReader

log = logging.getLogger("poi")


@dataclass
class RunSpec:
    run_dir: Path
    policy_path: Path
    key_path: Path
    image: str
    command: list[str] | None = None
    fingerprints: tuple[Path, bytes] | None = None
    extra_ro_mounts: dict[str, str] | None = None
    max_ticks: int | None = None
    gpus: str | None = None
    shm_size: str | None = None
    env: dict[str, str] | None = None
    sealed: SealedOptions | None = None
    gpu_runtime: str | None = None                 # e.g. "nvidia": GPUs via that runtime instead of --gpus


def _engine(client, rt: Runtime, policy: pol.Policy, key_path: Path, output_dir: Path | None = None,
            sealer=None, sealed_info: dict | None = None) -> Engine:
    w = rt.workload()
    out_dir = output_dir or rt.run_dir / "out"
    output = (out_dir, policy.output_volume) if policy.output_volume else None
    tracker = StateTracker(DockerContainerFS(client, w), output, image_mode=policy.image_attestation,
                           attest_mounts=tuple(policy.attest_mounts), sealer=sealer, sealed_info=sealed_info)
    on_violation = rt.pause if policy.on_violation == "pause" else (lambda v: log.warning("violation: %s", v))
    return Engine(Ledger(rt.run_dir, load_key(key_path)), tracker, WalReader(rt.run_dir / "proxy-wal"),
                  LocalPublisher(rt.run_dir), policy, {"id": w.id, "image": w.attrs["Image"]},
                  on_violation=on_violation)


def loop(engine: Engine, rt: Runtime, tick_seconds: float, max_ticks: int | None = None) -> None:
    """Tick until the workload exits (then one final tick) or Ctrl-C."""
    n = 0
    try:
        while max_ticks is None or n < max_ticks:
            time.sleep(tick_seconds)
            w = rt.workload()
            w.reload()
            cp = engine.tick()
            n += 1
            log.info("checkpoint %d state=%s egress=%d", cp["seq"], cp["state"]["digest"][:12],
                     cp["egress"]["count"])
            if w.status == "exited":
                time.sleep(0.5)          # let the proxy flush the last WAL lines
                engine.tick(final=True)  # signed end of run: the data owner's dashboard stops expecting more
                return
    except KeyboardInterrupt:
        engine.tick()


def start(spec: RunSpec, client=None) -> Runtime:
    client = client or docker.from_env()
    policy = pol.load(spec.policy_path)
    ensure_proxy_image(client)
    if spec.sealed is not None:
        return _start_sealed(spec, client, policy)
    rt = Runtime(client, spec.run_dir)
    rt.prepare(spec.policy_path, spec.fingerprints, policy.upstream_insecure)
    rt.create_workload(spec.image, spec.command, policy.output_volume, spec.extra_ro_mounts,
                       spec.gpus, spec.shm_size, spec.env, gpu_runtime=spec.gpu_runtime)
    engine = _engine(client, rt, policy, spec.key_path)
    engine.genesis()
    rt.workload().start()
    loop(engine, rt, policy.tick_seconds, spec.max_ticks)
    return rt


def _start_sealed(spec: RunSpec, client, policy: pol.Policy) -> Runtime:
    """Spec §6: everything decrypted lives in tmpfs; the workload is always removed and tmpfs wiped."""
    s = SealedSession(spec.run_dir, spec.sealed)
    rt = Runtime(client, spec.run_dir)
    try:
        s.setup(want_fingerprint_key=spec.fingerprints is not None)
        rt.prepare(spec.policy_path, spec.fingerprints, policy.upstream_insecure,
                   run_id=s.run_id, secrets_dir=s.secrets, no_logs=True)
        rt.create_workload(spec.image, spec.command, policy.output_volume,
                           {**(spec.extra_ro_mounts or {}), **s.ro_mounts}, spec.gpus, spec.shm_size, spec.env,
                           output_dir=s.out, read_only=True, tmpfs=spec.sealed.tmpfs, no_logs=True,
                           gpu_runtime=spec.gpu_runtime)
        engine = _engine(client, rt, policy, spec.key_path, output_dir=s.out, sealer=s.sealer,
                         sealed_info=s.config_info(policy.output_volume))
        engine.genesis()
        rt.workload().start()
        loop(engine, rt, policy.tick_seconds, spec.max_ticks)
        s.finish()
    finally:
        try:
            if rt.info is not None:
                rt.teardown(keep_workload=False)
        finally:                              # decrypted data must go even if Docker cleanup fails
            s.wipe(root_rm=lambda p: root_rm(client, p))
    return rt


def resume(run_dir: Path, key_path: Path, client=None, max_ticks: int | None = None) -> Runtime:
    if (Path(run_dir) / "sealed.json").exists():
        raise SealError("sealed runs cannot be resumed: their keys existed only in the stopped process")
    client = client or docker.from_env()
    rt = Runtime(client, run_dir, RuntimeInfo.load(run_dir))
    policy = pol.load(rt.run_dir / "policy.yaml")
    engine = _engine(client, rt, policy, key_path)
    engine.resume()
    loop(engine, rt, policy.tick_seconds, max_ticks)
    return rt
