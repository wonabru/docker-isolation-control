"""Container state as a set of `file` elements plus one `config` element.

Genesis and full scans read `docker export` (a tar of the merged filesystem); ticks
re-read only the paths reported by `docker diff`, which is the overlay upper layer.
Mount destinations are excluded from file scanning: mounts are attested by the
config element, and the declared output volume is scanned from its host directory.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat as st
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Protocol

from poi import canonical as c
from poi.ledger import DeltaOp

CONFIG_KEY = "\0config"
KIND_DELETED = 2
_CHUNK = 1 << 20


class ContainerFS(Protocol):
    def export(self) -> Iterable[bytes]: ...
    def export_image(self) -> Iterable[bytes]: ...
    def diff(self) -> list[dict]: ...
    def stat(self, path: str) -> dict | None: ...
    def archive(self, path: str) -> Iterable[bytes]: ...
    def inspect(self) -> dict: ...
    def network_internal(self, name: str) -> bool: ...


class _ChunkReader(io.RawIOBase):
    """File-like view over an iterator of byte chunks (for streaming tarfile)."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._it: Iterator[bytes] = iter(chunks)
        self._buf = b""

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        while not self._buf:
            try:
                self._buf = next(self._it)
            except StopIteration:
                return 0
        n = min(len(b), len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n


def _digest_stream(f) -> str:
    h = hashlib.blake2b(digest_size=32)
    while chunk := f.read(_CHUNK):
        h.update(chunk)
    return h.hexdigest()


def _member_element(path: str, m: tarfile.TarInfo, tar: tarfile.TarFile,
                    digests: dict[str, str]) -> bytes:
    if m.isreg():
        d = _digest_stream(tar.extractfile(m))
        digests[path] = d
        return c.file_element(path, "file", m.mode, m.uid, m.gid, d)
    if m.islnk():  # hard link: same bytes as its (earlier) target, as `docker cp` would show
        target = "/" + m.linkname.lstrip("./")
        return c.file_element(path, "file", m.mode, m.uid, m.gid, digests.get(target, ""))
    if m.issym():
        return c.file_element(path, "symlink", m.mode, m.uid, m.gid, m.linkname)
    if m.isdir():
        return c.file_element(path, "dir", m.mode, m.uid, m.gid, "")
    return c.file_element(path, "special", m.mode, m.uid, m.gid, "")


def _norm(name: str) -> str:
    name = name.lstrip(".").strip("/")
    return "/" + name if name else ""


def _excluded(path: str, excludes: tuple[str, ...]) -> bool:
    return any(path == e or path.startswith(e + "/") for e in excludes)


def scan_tar(chunks: Iterable[bytes], excludes: tuple[str, ...] = ()) -> dict[str, bytes]:
    """Full filesystem tar → {path: element}."""
    out: dict[str, bytes] = {}
    digests: dict[str, str] = {}
    with tarfile.open(fileobj=io.BufferedReader(_ChunkReader(chunks)), mode="r|") as tar:
        for m in tar:
            path = _norm(m.name)
            if path and not _excluded(path, excludes):
                out[path] = _member_element(path, m, tar, digests)
    return out


def element_from_archive(path: str, chunks: Iterable[bytes]) -> bytes | None:
    """`docker cp`-style archive of one path → element of that path (first tar member)."""
    with tarfile.open(fileobj=io.BufferedReader(_ChunkReader(chunks)), mode="r|") as tar:
        for m in tar:
            return _member_element(path, m, tar, {})
    return None


def scan_host_dir(host_dir: Path, target: str) -> dict[str, bytes]:
    """Scan the output volume on the host; elements use container paths under `target`."""
    out: dict[str, bytes] = {}
    host_dir = Path(host_dir)
    for root, dirs, files in os.walk(host_dir):
        for name in sorted(dirs) + sorted(files):
            p = Path(root) / name
            s = os.lstat(p)
            cpath = target.rstrip("/") + "/" + str(p.relative_to(host_dir))
            if st.S_ISREG(s.st_mode):
                with open(p, "rb") as f:
                    content, ftype = _digest_stream(f), "file"
            elif st.S_ISLNK(s.st_mode):
                content, ftype = os.readlink(p), "symlink"
            elif st.S_ISDIR(s.st_mode):
                content, ftype = "", "dir"
            else:
                content, ftype = "", "special"
            out[cpath] = c.file_element(cpath, ftype, s.st_mode, s.st_uid, s.st_gid, content)
    return out


def config_doc(inspect: dict, network_internal) -> dict:
    """Security-relevant container configuration (spec §5.2 `config`)."""
    hc = inspect["HostConfig"]
    nets = inspect["NetworkSettings"]["Networks"] or {}
    return {
        "image": inspect["Image"],
        "user": inspect["Config"].get("User", ""),
        "privileged": bool(hc.get("Privileged")),
        "cap_add": sorted(hc.get("CapAdd") or []),
        "network_mode": hc.get("NetworkMode", ""),
        "networks": [{"name": n, "internal": network_internal(n)} for n in sorted(nets)],
        "mounts": sorted(({"destination": m["Destination"], "rw": bool(m["RW"]), "type": m["Type"]}
                          for m in inspect.get("Mounts", [])), key=lambda m: m["destination"]),
        "dns": list(hc.get("Dns") or []),
        "pid_mode": hc.get("PidMode", ""),
        "ipc_mode": hc.get("IpcMode", ""),
        "devices": len(hc.get("Devices") or []),
    }


def config_bytes(doc: dict) -> bytes:
    return c.canonical_json(doc)


@dataclass
class _Cached:
    stat_key: str
    element: bytes


class StateTracker:
    def __init__(self, fs: ContainerFS, output: tuple[Path, str] | None = None,
                 retries: int = 3) -> None:
        self.fs = fs
        self.output = output
        self.retries = retries
        self.index: dict[str, bytes] = {}
        self.image_index: dict[str, bytes] = {}
        self._cache: dict[str, _Cached] = {}
        self.last_config: bytes = b""

    # -- helpers --------------------------------------------------------------
    def _excludes(self, inspect: dict) -> tuple[str, ...]:
        return tuple(sorted(m["Destination"] for m in inspect.get("Mounts", [])))

    def _config(self, inspect: dict) -> tuple[str, bytes]:
        raw = config_bytes(config_doc(inspect, self.fs.network_internal))
        self.last_config = raw
        return c.b2b256(raw), c.config_element(c.b2b256(raw))

    def _element(self, path: str) -> bytes | None:
        """Re-hash a changed path; stat before/after must agree (else retry, then defer)."""
        for _ in range(self.retries):
            before = self.fs.stat(path)
            if before is None:
                return None
            key = json.dumps(before, sort_keys=True)
            cached = self._cache.get(path)
            if cached and cached.stat_key == key:
                return cached.element
            el = element_from_archive(path, self.fs.archive(path))
            if el is not None and self.fs.stat(path) == before:
                self._cache[path] = _Cached(key, el)
                return el
        return self.index.get(path)  # unstable: keep last known value, retry next tick

    # -- public API -------------------------------------------------------------
    def load_image(self) -> None:
        self.image_index = scan_tar(self.fs.export_image(), self._excludes(self.fs.inspect()))

    def target(self, full: bool = False) -> dict[str, bytes]:
        inspect = self.fs.inspect()
        excludes = self._excludes(inspect)
        if full:
            t = scan_tar(self.fs.export(), excludes)
        else:
            t = dict(self.image_index)
            changes = [d for d in self.fs.diff() if not _excluded(d["Path"], excludes)]
            for d in changes:
                if d["Kind"] == KIND_DELETED:
                    p = d["Path"]
                    for k in [k for k in t if k == p or k.startswith(p + "/")]:
                        del t[k]
            for d in changes:
                if d["Kind"] != KIND_DELETED:
                    el = self._element(d["Path"])
                    if el is not None:
                        t[d["Path"]] = el
        if self.output is not None:
            t.update(scan_host_dir(*self.output))
        _, cfg = self._config(inspect)
        t[CONFIG_KEY] = cfg
        return t

    def update(self, full: bool = False) -> list[DeltaOp]:
        """Compute target state and return the ops that move `index` to it."""
        target = self.target(full)
        ops: list[DeltaOp] = []
        for k in sorted(self.index.keys() - target.keys()):
            ops.append(DeltaOp("sub", "state", self.index[k]))
        for k in sorted(target.keys()):
            old = self.index.get(k)
            if old != target[k]:
                if old is not None:
                    ops.append(DeltaOp("sub", "state", old))
                ops.append(DeltaOp("add", "state", target[k]))
        self.index = target
        return ops

    def restore_index(self, elements: Iterable[bytes]) -> None:
        """Rebuild the path index from replayed ledger elements (daemon restart)."""
        self.index = {}
        for e in elements:
            f = c.decode(e)
            self.index[CONFIG_KEY if f[0] == "config" else f[1]] = e


class DockerContainerFS:
    """ContainerFS backed by the Docker Engine API (no root needed, only docker group)."""

    def __init__(self, client, container) -> None:
        self.client = client
        self.container = container

    def export(self) -> Iterable[bytes]:
        return self.container.export()

    def export_image(self) -> Iterable[bytes]:
        tmp = self.client.containers.create(self.container.attrs["Image"], command=["true"])
        try:
            yield from tmp.export()
        finally:
            tmp.remove(force=True)

    def diff(self) -> list[dict]:
        return self.container.diff() or []

    def stat(self, path: str) -> dict | None:
        api = self.client.api
        r = api.head(api._url("/containers/{0}/archive", self.container.id), params={"path": path})
        if r.status_code != 200:
            return None
        return json.loads(base64.b64decode(r.headers["X-Docker-Container-Path-Stat"]))

    def archive(self, path: str) -> Iterable[bytes]:
        stream, _ = self.container.get_archive(path)
        return stream

    def inspect(self) -> dict:
        self.container.reload()
        return self.container.attrs

    def network_internal(self, name: str) -> bool:
        if name in ("bridge", "host", "none"):
            return name == "none"
        return bool(self.client.networks.get(name).attrs.get("Internal"))
