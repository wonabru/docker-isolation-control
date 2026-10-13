"""`poi serve`: read-only HTTP feed of a run directory for the data owner's dashboard.

Serves raw bytes from disk only; all trust comes from signatures verified on the owner's side.
Bind to localhost and put TLS in front (Caddy/nginx).
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

MAX_WAIT = 30.0
MAX_BATCH = 500
_SEQ = re.compile(r"^\d{1,9}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def new_token(path: Path) -> str:
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    return token


class _Cached:
    def __init__(self, fn: Callable[[], dict], ttl: float) -> None:
        self.fn, self.ttl = fn, ttl
        self._at, self._val = -1e9, None
        self._lock = threading.Lock()

    def get(self) -> dict:
        with self._lock:
            if time.monotonic() - self._at > self.ttl:
                self._val, self._at = self.fn(), time.monotonic()
            return self._val


def make_server(run_dir: Path, token: str, host: str = "127.0.0.1", port: int = 8765,
                runtime: Callable[[], dict] | None = None, poll: float = 0.2) -> ThreadingHTTPServer:
    run_dir = Path(run_dir)
    rt = _Cached(runtime or (lambda: {"status": "unknown"}), ttl=2.0)
    expected = f"Bearer {token}".encode()

    def checkpoint_batch(start: int) -> list[bytes]:
        out = []
        for seq in range(start, start + MAX_BATCH):
            p = run_dir / "ledger" / f"{seq:06d}.json"
            try:
                out.append(p.read_bytes())
            except FileNotFoundError:
                break
        return out

    class Handler(BaseHTTPRequestHandler):
        server_version = "poi-serve"

        def log_message(self, *args) -> None:
            pass

        def _send(self, code: int, body: bytes, ctype: str = "application/octet-stream") -> None:
            self.send_response(code)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _file(self, path: Path, ctype: str = "application/octet-stream") -> None:
            try:
                self._send(200, path.read_bytes(), ctype)
            except FileNotFoundError:
                self._send(404, b"not found\n", "text/plain")

        def do_GET(self) -> None:
            auth = (self.headers.get("authorization") or "").encode()
            if not hmac.compare_digest(auth, expected):
                return self._send(401, b"unauthorized\n", "text/plain")
            url = urlsplit(self.path)
            parts = url.path.strip("/").split("/")
            if parts[:1] != ["v1"] or len(parts) < 2:
                return self._send(404, b"not found\n", "text/plain")
            kind, arg = parts[1], (parts[2] if len(parts) == 3 else None)
            if kind == "checkpoints" and arg is None:
                q = parse_qs(url.query)
                try:
                    start = int(q.get("from", ["0"])[0])
                    wait = min(float(q.get("wait", ["0"])[0]), MAX_WAIT)
                except ValueError:
                    return self._send(400, b"bad query\n", "text/plain")
                if start < 0 or wait < 0:
                    return self._send(400, b"bad query\n", "text/plain")
                deadline = time.monotonic() + wait
                batch = checkpoint_batch(start)
                while not batch and time.monotonic() < deadline:
                    time.sleep(poll)
                    batch = checkpoint_batch(start)
                return self._send(200, b"[" + b",".join(batch) + b"]", "application/json")
            if kind == "delta" and arg is not None:
                if not _SEQ.match(arg):
                    return self._send(400, b"bad seq\n", "text/plain")
                return self._file(run_dir / "delta" / f"{int(arg):06d}.jsonl")
            if kind == "evidence" and arg is not None:
                if not _DIGEST.match(arg):
                    return self._send(400, b"bad digest\n", "text/plain")
                return self._file(run_dir / "evidence" / f"{arg}.bin")
            if kind == "policy" and arg is None:
                return self._file(run_dir / "policy.yaml", "application/yaml")
            if kind == "runtime" and arg is None:
                return self._send(200, json.dumps(rt.get()).encode(), "application/json")
            return self._send(404, b"not found\n", "text/plain")

    return ThreadingHTTPServer((host, port), Handler)
