"""Keyed winnowing fingerprints of user data and their detection in outbound bytes (informative layer)."""
from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import re
import urllib.parse
from pathlib import Path

_B64_RUN = re.compile(rb"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RUN = re.compile(rb"(?:[0-9a-fA-F]{2}){8,}")
_WS = re.compile(rb"\s+")


def normalize(data: bytes) -> bytes:
    return _WS.sub(b"", data).lower()


def _kgram_hashes(data: bytes, k: int, key: bytes) -> list[int]:
    return [
        int.from_bytes(hashlib.blake2b(data[i:i + k], digest_size=8, key=key).digest(), "big")
        for i in range(len(data) - k + 1)
    ]


def winnow(data: bytes, key: bytes, k: int = 32, w: int = 16) -> set[int]:
    """Winnowing (Schleimer et al. 2003): any shared substring of length >= w+k-1
    of the normalised inputs yields at least one shared fingerprint."""
    hs = _kgram_hashes(normalize(data), k, key)
    if not hs:
        return set()
    if len(hs) <= w:
        return {min(hs)}
    return {min(hs[i:i + w]) for i in range(len(hs) - w + 1)}


def variants(data: bytes, depth: int = 2) -> list[bytes]:
    """The raw bytes plus decodings an exfiltrating workload might use."""
    out = [data]
    frontier = [data]
    for _ in range(depth):
        nxt = []
        for d in frontier:
            if d[:2] == b"\x1f\x8b":
                try:
                    nxt.append(gzip.decompress(d))
                except (OSError, EOFError):
                    pass
            unq = urllib.parse.unquote_to_bytes(d)
            if unq != d:
                nxt.append(unq)
            for m in _B64_RUN.finditer(d):
                s = m.group(0)
                for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                    try:
                        nxt.append(decoder(s + b"=" * (-len(s) % 4)))
                        break
                    except (binascii.Error, ValueError):
                        continue
            for m in _HEX_RUN.finditer(d):
                nxt.append(binascii.unhexlify(m.group(0)))
        out += nxt
        frontier = nxt
    return out


class FingerprintSet:
    def __init__(self, key: bytes, k: int = 32, w: int = 16, prints: set[int] | None = None) -> None:
        self.key, self.k, self.w = key, k, w
        self.prints: set[int] = prints if prints is not None else set()
        self.sources: dict[int, str] = {}

    def add(self, data: bytes, source: str = "") -> None:
        for fp in winnow(data, self.key, self.k, self.w):
            self.prints.add(fp)
            self.sources.setdefault(fp, source)

    @classmethod
    def from_dir(cls, data_dir: Path, key: bytes, k: int = 32, w: int = 16) -> "FingerprintSet":
        fs = cls(key, k, w)
        for p in sorted(Path(data_dir).rglob("*")):
            if p.is_file():
                fs.add(p.read_bytes(), str(p.relative_to(data_dir)))
        return fs

    def scan(self, outbound: bytes) -> set[str]:
        """Return the sources whose fingerprints occur in `outbound` or any decoded variant."""
        hits: set[str] = set()
        for v in variants(outbound):
            for fp in winnow(v, self.key, self.k, self.w) & self.prints:
                hits.add(self.sources.get(fp, "?"))
        return hits

    def save(self, path: Path) -> None:
        Path(path).write_bytes(b"".join(fp.to_bytes(8, "big") for fp in sorted(self.prints)))

    @classmethod
    def load(cls, path: Path, key: bytes, k: int = 32, w: int = 16) -> "FingerprintSet":
        raw = Path(path).read_bytes()
        return cls(key, k, w, {int.from_bytes(raw[i:i + 8], "big") for i in range(0, len(raw), 8)})
