"""Canonical byte encodings shared by every component (daemon, proxy, verifier)."""
from __future__ import annotations

import hashlib
import json
from typing import Any

SEP = b"\0"


def b2b256(data: bytes) -> str:
    """Hex BLAKE2b-256 used for content digests everywhere in poi."""
    return hashlib.blake2b(data, digest_size=32).hexdigest()


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _field(v: str | int) -> bytes:
    b = str(v).encode("utf-8")
    if SEP in b:
        raise ValueError(f"field contains NUL: {v!r}")
    return b


def encode(domain: str, *fields: str | int) -> bytes:
    return SEP.join([_field(domain), *(_field(f) for f in fields)])


def decode(element: bytes) -> list[str]:
    return element.decode("utf-8").split("\0")


# --- element constructors (spec §5.2) ---------------------------------------

def file_element(path: str, ftype: str, mode: int, uid: int, gid: int, content: str) -> bytes:
    """ftype: file|dir|symlink|special. content: digest (file), link target (symlink), '' otherwise."""
    return encode("file", path, ftype, format(mode & 0o7777, "o"), uid, gid, content)


def config_element(config_digest: str) -> bytes:
    return encode("config", config_digest)


def egress_element(seq: int, t: str, method: str, host: str, path: str,
                   headers_digest: str, body_digest: str, verdict: str, reason: str) -> bytes:
    return encode("egress", seq, t, method, host, path, headers_digest, body_digest, verdict, reason)


def dns_element(seq: int, t: str, name: str, qtype: str, verdict: str) -> bytes:
    return encode("dns", seq, t, name, qtype, verdict)


def ingress_element(seq: int, status: int, headers_digest: str, body_digest: str) -> bytes:
    return encode("ingress", seq, status, headers_digest, body_digest)


def headers_digest(headers: list[tuple[str, str]]) -> str:
    """Order-independent, case-normalised digest of HTTP headers."""
    norm = sorted((k.lower(), v) for k, v in headers)
    return b2b256(canonical_json(norm))


# --- checkpoints -------------------------------------------------------------

def checkpoint_signing_bytes(cp: dict) -> bytes:
    """Bytes covered by the signature and by the next checkpoint's `prev`."""
    return canonical_json({k: v for k, v in cp.items() if k != "sig"})


def checkpoint_digest(cp: dict) -> str:
    return b2b256(checkpoint_signing_bytes(cp))
