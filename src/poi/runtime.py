"""Docker orchestration: networks, proxy container, workload container."""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

import docker
from docker.errors import APIError, ImageNotFound, NotFound

PROXY_IMAGE = "poi-proxy:0.2"
SECRETS_IN_PROXY = "/run/poi-secrets"     # must match POI_SECRETS in proxy_addon.py
PROXY_PORT = 8080
CA_IN_WORKLOAD = "/etc/poi/ca.pem"
REPO_ROOT = Path(__file__).resolve().parents[2]   # src layout: <repo>/src/poi/runtime.py


@dataclass
class RuntimeInfo:
    run_id: str
    int_network: str
    ext_network: str
    proxy_ip: str
    proxy_id: str = ""
    workload_id: str = ""
    extra_networks: list[str] = field(default_factory=list)

    def save(self, run_dir: Path) -> None:
        (Path(run_dir) / "runtime.json").write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, run_dir: Path) -> "RuntimeInfo":
        return cls(**json.loads((Path(run_dir) / "runtime.json").read_text()))


def build_proxy_image(client: docker.DockerClient, tag: str = PROXY_IMAGE) -> None:
    client.images.build(path=str(REPO_ROOT), dockerfile="docker/proxy.Dockerfile", tag=tag, rm=True)


def ensure_proxy_image(client: docker.DockerClient, tag: str = PROXY_IMAGE) -> None:
    """Build the proxy image on first use (needs network access for pip)."""
    try:
        client.images.get(tag)
    except ImageNotFound:
        build_proxy_image(client, tag)


def root_rm(client: docker.DockerClient, path: Path, image: str = PROXY_IMAGE) -> None:
    """Remove the contents of a host directory as uid 0 (files the workload wrote belong to root)."""
    client.containers.run(image, entrypoint=["sh", "-c", "rm -rf /w/* /w/.[!.]* 2>/dev/null; true"],
                          user="0:0", network_mode="none", remove=True,
                          volumes={str(path): {"bind": "/w", "mode": "rw"}})


def visible_devices(gpus: str) -> str:
    """NVIDIA_VISIBLE_DEVICES for `gpus`: "all", device ids "0,1" as given, a count N → "0,…,N-1"."""
    if gpus == "all" or "," in gpus:
        return gpus
    return ",".join(str(i) for i in range(int(gpus)))


class Runtime:
    def __init__(self, client: docker.DockerClient, run_dir: Path, info: RuntimeInfo | None = None) -> None:
        self.client = client
        self.run_dir = Path(run_dir).resolve()
        self.info = info

    # -- setup -------------------------------------------------------------------
    def _create_internal_network(self, name: str):
        for third in range(256):
            subnet = ipaddress.ip_network(f"10.231.{third}.0/24")
            ipam = docker.types.IPAMConfig(pool_configs=[docker.types.IPAMPool(subnet=str(subnet))])
            try:
                return self.client.networks.create(name, driver="bridge", internal=True, ipam=ipam), subnet
            except APIError as e:
                if "overlap" not in str(e).lower():
                    raise
        raise RuntimeError("no free 10.231.x.0/24 subnet for the internal network")

    def prepare(self, policy_path: Path, fingerprints: tuple[Path, bytes | None] | None = None,
                upstream_insecure: bool = False, proxy_image: str = PROXY_IMAGE, run_id: str | None = None,
                secrets_dir: Path | None = None, no_logs: bool = False) -> RuntimeInfo:
        """Create networks and start the proxy. Copies policy (and fingerprints) into the run dir.

        Sealed mode passes `secrets_dir` (tmpfs, mounted read-only into the proxy), no fingerprint key
        and `no_logs` (mitmdump prints request lines)."""
        self.run_dir.mkdir(parents=True, exist_ok=True)
        for d in ("ca", "proxy-wal", "evidence", "out"):
            (self.run_dir / d).mkdir(exist_ok=True)
        shutil.copyfile(policy_path, self.run_dir / "policy.yaml")
        if fingerprints is not None:
            shutil.copyfile(fingerprints[0], self.run_dir / "fingerprints.bin")
            if fingerprints[1] is not None:
                kp = self.run_dir / "fingerprint.key"
                kp.write_bytes(fingerprints[1])
                os.chmod(kp, 0o600)
        run_id = run_id or uuid.uuid4().hex[:8]
        net, subnet = self._create_internal_network(f"poi-{run_id}-int")
        ext = self.client.networks.create(f"poi-{run_id}-ext", driver="bridge")
        proxy_ip = str(subnet.network_address + 2)
        self.info = RuntimeInfo(run_id, net.name, ext.name, proxy_ip)
        cmd = ["--set", "ssl_insecure=true"] if upstream_insecure else []
        volumes = {str(self.run_dir): {"bind": "/run/poi", "mode": "rw"}}
        if secrets_dir is not None:
            volumes[str(secrets_dir)] = {"bind": SECRETS_IN_PROXY, "mode": "ro"}
        extra = {"log_config": docker.types.LogConfig(type="none")} if no_logs else {}
        proxy = self.client.containers.create(
            proxy_image, command=cmd, name=f"poi-{run_id}-proxy", network=ext.name,
            user=f"{os.getuid()}:{os.getgid()}",
            environment={"POI_PROXY_IP": proxy_ip},
            sysctls={"net.ipv4.ip_unprivileged_port_start": "0"},
            volumes=volumes, **extra)
        net.connect(proxy, ipv4_address=proxy_ip)
        proxy.start()
        self.info.proxy_id = proxy.id
        self._wait_for_ca(proxy)
        self.info.save(self.run_dir)
        return self.info

    def _wait_for_ca(self, proxy, timeout: float = 30) -> None:
        ca = self.run_dir / "ca" / "mitmproxy-ca-cert.pem"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            proxy.reload()
            if proxy.status == "exited":
                try:
                    logs = proxy.logs().decode(errors="replace")
                except APIError:
                    logs = "(proxy logs disabled)"
                raise RuntimeError("proxy exited:\n" + logs)
            if ca.exists():
                probe = "import socket; socket.create_connection(('127.0.0.1', %d), 1)" % PROXY_PORT
                if proxy.exec_run(["python", "-c", probe]).exit_code == 0:
                    return
            time.sleep(0.2)
        raise TimeoutError("proxy did not become ready")

    def create_workload(self, image: str, command: list[str] | None, output_target: str | None,
                        extra_ro_mounts: dict[str, str] | None = None, gpus: str | None = None,
                        shm_size: str | None = None, env: dict[str, str] | None = None, *,
                        output_dir: Path | None = None, read_only: bool = False,
                        tmpfs: list[str] | None = None, no_logs: bool = False, gpu_runtime: str | None = None):
        """Create (not start) the workload: internal network only, proxy env, CA, DNS → stub.

        Sealed mode: `output_dir` on tmpfs, read-only root filesystem, `tmpfs` scratch paths, no logs.
        A tmpfs entry is a path or "PATH:OPTIONS" (Docker tmpfs options, e.g. "/jit:exec" for JIT kernel caches;
        Docker mounts tmpfs noexec by default).
        GPUs: `gpus` is "all", a count or device ids ("0,1"); by default a device request (`docker --gpus`),
        with `gpu_runtime` (e.g. "nvidia") that runtime + NVIDIA_VISIBLE_DEVICES — for hosts whose NVIDIA
        Container Toolkit runs in CDI mode, where `--gpus` is refused."""
        i = self.info
        proxy_url = f"http://{i.proxy_ip}:{PROXY_PORT}"
        volumes = {str(self.run_dir / "ca" / "mitmproxy-ca-cert.pem"): {"bind": CA_IN_WORKLOAD, "mode": "ro"}}
        if output_target:
            volumes[str(output_dir or self.run_dir / "out")] = {"bind": output_target, "mode": "rw"}
        for host, target in (extra_ro_mounts or {}).items():
            volumes[str(Path(host).resolve())] = {"bind": target, "mode": "ro"}
        env = dict(env or {})                    # poi's proxy and CA settings always win
        env.update({k: proxy_url for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")})
        env.update({k: CA_IN_WORKLOAD for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                                                 "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE")})
        extra = {}
        if gpus and gpu_runtime:
            extra["runtime"] = gpu_runtime
            env["NVIDIA_VISIBLE_DEVICES"] = visible_devices(gpus)
            env.setdefault("NVIDIA_DRIVER_CAPABILITIES", "compute,utility")
        elif gpus:
            if "," in gpus:
                req = docker.types.DeviceRequest(device_ids=gpus.split(","), capabilities=[["gpu"]])
            else:
                req = docker.types.DeviceRequest(count=-1 if gpus == "all" else int(gpus), capabilities=[["gpu"]])
            extra["device_requests"] = [req]
        if shm_size:
            extra["shm_size"] = shm_size
        if read_only:
            extra["read_only"] = True
        if tmpfs:
            extra["tmpfs"] = dict(t.split(":", 1) if ":" in t else (t, "") for t in tmpfs)
        if no_logs:
            extra["log_config"] = docker.types.LogConfig(type="none")
        w = self.client.containers.create(
            image, command=command, name=f"poi-{i.run_id}-workload", network=i.int_network,
            dns=[i.proxy_ip], environment=env, volumes=volumes, **extra)
        i.workload_id = w.id
        i.save(self.run_dir)
        return w

    # -- control -------------------------------------------------------------------
    def workload(self):
        return self.client.containers.get(self.info.workload_id)

    def proxy(self):
        return self.client.containers.get(self.info.proxy_id)

    def pause(self, violations: list[str]) -> None:
        w = self.workload()
        w.reload()
        if w.status == "running":
            w.pause()

    def teardown(self, keep_workload: bool = True) -> None:
        """Remove the proxy and external network. The stopped workload and its internal
        network are kept by default so `poi verify --live` can still inspect them."""
        cids = [self.info.proxy_id] + ([] if keep_workload else [self.info.workload_id])
        nets = [self.info.ext_network] + ([] if keep_workload else [self.info.int_network])
        for cid in cids:
            if cid:
                try:
                    self.client.containers.get(cid).remove(force=True)
                except NotFound:
                    pass
        for n in nets:
            try:
                self.client.networks.get(n).remove()
            except NotFound:
                pass
