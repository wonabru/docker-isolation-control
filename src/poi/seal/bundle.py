"""Sealed bundle (*.sealed): a tar of a directory encrypted in authenticated chunks (spec §5.5).

Chunk i uses nonce = prefix(7) ‖ u32 i ‖ u8 last and the header bytes as AAD, so truncation,
reordering and header edits all fail authentication. Plaintext is only ever yielded after its
chunk has been authenticated.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import struct
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from poi.canonical import canonical_json
from poi.seal import SealError, b64d, b64e, kem

MAGIC = b"POISEAL1"
CHUNK = 1 << 20
TAG = 16
DEK_AAD = b"poi-dek"
MAX_HEADER = 1 << 16


@dataclass
class Header:
    raw: bytes
    kind: str
    chunk: int
    prefix: bytes
    dek_wrap: bytes


def _nonce(prefix: bytes, i: int, last: bool) -> bytes:
    return prefix + struct.pack(">IB", i, int(last))


class _EncWriter:
    """Write-only sink for tarfile: keeps one chunk buffered so the final chunk can carry last=1."""

    def __init__(self, out: BinaryIO, aead: AESGCM, prefix: bytes, aad: bytes, chunk: int) -> None:
        self.out, self.aead, self.prefix, self.aad, self.chunk = out, aead, prefix, aad, chunk
        self.buf = bytearray()
        self.i = 0

    def write(self, b) -> int:
        self.buf += b
        while len(self.buf) > self.chunk:
            self._emit(bytes(self.buf[:self.chunk]), False)
            del self.buf[:self.chunk]
        return len(b)

    def _emit(self, data: bytes, last: bool) -> None:
        self.out.write(self.aead.encrypt(_nonce(self.prefix, self.i, last), data, self.aad))
        self.i += 1

    def finish(self) -> None:
        self._emit(bytes(self.buf), True)
        self.buf.clear()


class _Reader:
    """read()-only view over an iterator of byte chunks (tarfile stream mode)."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self.it: Iterator[bytes] = iter(chunks)
        self.cur = io.BytesIO(b"")

    def read(self, n: int = -1) -> bytes:
        out = bytearray()
        while n < 0 or len(out) < n:
            piece = self.cur.read(-1 if n < 0 else n - len(out))
            if piece:
                out += piece
                continue
            try:
                self.cur = io.BytesIO(next(self.it))
            except StopIteration:
                break
        return bytes(out)


def _strip_owner(ti: tarfile.TarInfo) -> tarfile.TarInfo:
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    return ti


def file_digest(path: Path) -> str:
    h = hashlib.blake2b(digest_size=32)
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def seal_dir(src: Path, out: Path, recipient_pub: bytes, kind: str = "data", chunk: int = CHUNK) -> str:
    """Encrypt directory `src` into `out` for `recipient_pub`. Returns the bundle digest."""
    dek = AESGCM.generate_key(bit_length=256)
    prefix = os.urandom(7)
    header = canonical_json({"v": 1, "kind": kind, "chunk": chunk, "prefix": b64e(prefix),
                             "dek_wrap": b64e(kem.wrap(recipient_pub, dek, DEK_AAD))})
    out = Path(out)
    tmp = out.with_name(out.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(MAGIC + struct.pack(">I", len(header)) + header)
        w = _EncWriter(f, AESGCM(dek), prefix, header, chunk)
        with tarfile.open(fileobj=w, mode="w|", format=tarfile.PAX_FORMAT) as tar:
            tar.add(str(src), arcname=".", filter=_strip_owner)
        w.finish()
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, out)
    return file_digest(out)


def read_header(f: BinaryIO) -> Header:
    try:
        if f.read(len(MAGIC)) != MAGIC:
            raise SealError("not a poi sealed bundle")
        (n,) = struct.unpack(">I", f.read(4))
        if n > MAX_HEADER:
            raise SealError("bundle header too large")
        raw = f.read(n)
        d = json.loads(raw)
        h = Header(raw, d["kind"], int(d["chunk"]), b64d(d["prefix"]), b64d(d["dek_wrap"]))
    except (struct.error, ValueError, KeyError, TypeError) as e:
        raise SealError(f"malformed bundle header: {e}") from e
    if len(h.prefix) != 7 or h.chunk <= 0:
        raise SealError("malformed bundle header")
    return h


def header_of(path: Path) -> Header:
    with open(path, "rb") as f:
        return read_header(f)


def dek_for(path: Path, client_sk: bytes) -> bytes:
    return kem.unwrap(client_sk, header_of(path).dek_wrap, DEK_AAD)


def decrypt_chunks(path: Path, dek: bytes) -> Iterator[bytes]:
    aead = AESGCM(dek)
    with open(path, "rb") as f:
        h = read_header(f)
        size = h.chunk + TAG
        cur, i = f.read(size), 0
        while True:
            nxt = f.read(size)
            last = not nxt
            if len(cur) < TAG or (not last and len(cur) != size):
                raise SealError("truncated bundle")
            try:
                yield aead.decrypt(_nonce(h.prefix, i, last), cur, h.raw)
            except InvalidTag:
                raise SealError(f"bundle chunk {i} failed authentication") from None
            if last:
                return
            cur, i = nxt, i + 1


def unseal_to(path: Path, dek: bytes, dest: Path) -> None:
    """Decrypt and extract into `dest` (tar 'data' filter: no absolute paths or escaping links)."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=_Reader(decrypt_chunks(Path(path), dek)), mode="r|") as tar:
        tar.extractall(dest, filter="data")
