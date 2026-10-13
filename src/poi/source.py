"""Where the dashboard reads a run from: the operator's `poi serve` (HTTP) or a local run directory."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Protocol


class SourceError(Exception):
    """Transport problem (unreachable, 5xx, malformed response)."""


class AuthError(SourceError):
    pass


class NotFound(SourceError):
    pass


class Source(Protocol):
    def checkpoints(self, start: int, wait: float) -> list[dict]: ...
    def delta(self, seq: int) -> bytes: ...
    def evidence(self, digest: str) -> bytes: ...
    def policy(self) -> bytes: ...
    def runtime(self) -> dict: ...


class LocalSource:
    def __init__(self, run_dir: Path, runtime: Callable[[], dict] | None = None, poll: float = 0.2) -> None:
        self.run_dir = Path(run_dir)
        self._runtime = runtime
        self.poll = poll

    def _read(self, path: Path) -> bytes:
        try:
            return path.read_bytes()
        except FileNotFoundError:
            raise NotFound(str(path))

    def checkpoints(self, start: int, wait: float) -> list[dict]:
        deadline = time.monotonic() + wait
        while True:
            out = []
            seq = start
            while (p := self.run_dir / "ledger" / f"{seq:06d}.json").exists():
                out.append(json.loads(p.read_bytes()))
                seq += 1
            if out or time.monotonic() >= deadline:
                return out
            time.sleep(self.poll)

    def delta(self, seq: int) -> bytes:
        return self._read(self.run_dir / "delta" / f"{seq:06d}.jsonl")

    def evidence(self, digest: str) -> bytes:
        return self._read(self.run_dir / "evidence" / f"{digest}.bin")

    def policy(self) -> bytes:
        return self._read(self.run_dir / "policy.yaml")

    def runtime(self) -> dict:
        if self._runtime is not None:
            return self._runtime()
        try:
            from poi.runtime import RuntimeInfo
            from poi.runtime_info import declaration
            import docker
            return declaration(docker.from_env(), RuntimeInfo.load(self.run_dir).workload_id)
        except Exception:
            return {"status": "unknown"}


class HttpSource:
    def __init__(self, base_url: str, token: str, timeout: float = 10.0) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _get(self, path: str, timeout: float | None = None) -> bytes:
        req = urllib.request.Request(self.base + path, headers={"authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise AuthError("operator rejected the token (401)")
            if e.code == 404:
                raise NotFound(path)
            raise SourceError(f"HTTP {e.code} for {path}")
        except (urllib.error.URLError, OSError) as e:
            raise SourceError(f"{type(e).__name__}: {e}")

    def checkpoints(self, start: int, wait: float) -> list[dict]:
        raw = self._get(f"/v1/checkpoints?from={start}&wait={wait:g}", timeout=wait + self.timeout)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise SourceError("malformed checkpoint list")
        if not isinstance(data, list) or not all(isinstance(cp, dict) for cp in data):
            raise SourceError("malformed checkpoint list")
        return data

    def delta(self, seq: int) -> bytes:
        return self._get(f"/v1/delta/{seq}")

    def evidence(self, digest: str) -> bytes:
        return self._get(f"/v1/evidence/{digest}")

    def policy(self) -> bytes:
        return self._get("/v1/policy")

    def runtime(self) -> dict:
        try:
            return json.loads(self._get("/v1/runtime"))
        except json.JSONDecodeError:
            raise SourceError("malformed runtime declaration")
