"""LtHash16: additive homomorphic multiset hash (Lewi et al., 2019) over BLAKE2b."""
from __future__ import annotations

import base64
import hashlib

import numpy as np

N = 1024                      # coordinates
VEC_BYTES = N * 2             # 2048 bytes
_BLOCKS = VEC_BYTES // 64     # 32 BLAKE2b-512 blocks
_PERSON_EXPAND = b"poi-lthash-v1"
_PERSON_DIGEST = b"poi-digest-v1"


def expand(element: bytes) -> np.ndarray:
    """Map an element to a pseudo-random vector of 1024 uint16 (BLAKE2b counter mode)."""
    out = bytearray()
    for i in range(_BLOCKS):
        out += hashlib.blake2b(
            i.to_bytes(4, "big") + element, digest_size=64, person=_PERSON_EXPAND
        ).digest()
    return np.frombuffer(bytes(out), dtype="<u2").copy()


class LtHash:
    """Value object: sum of expanded elements mod 2**16."""

    __slots__ = ("vec",)

    def __init__(self, vec: np.ndarray | None = None) -> None:
        if vec is None:
            vec = np.zeros(N, dtype="<u2")
        if vec.shape != (N,) or vec.dtype != np.dtype("<u2"):
            raise ValueError("LtHash vector must be 1024 little-endian uint16")
        self.vec = vec

    @classmethod
    def of(cls, elements) -> "LtHash":
        h = cls()
        for e in elements:
            h.add(e)
        return h

    def add(self, element: bytes) -> "LtHash":
        self.vec += expand(element)  # uint16 arithmetic wraps mod 2**16
        return self

    def sub(self, element: bytes) -> "LtHash":
        self.vec -= expand(element)
        return self

    def __add__(self, other: "LtHash") -> "LtHash":
        return LtHash(self.vec + other.vec)

    def __sub__(self, other: "LtHash") -> "LtHash":
        return LtHash(self.vec - other.vec)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, LtHash) and bool(np.array_equal(self.vec, other.vec))

    def copy(self) -> "LtHash":
        return LtHash(self.vec.copy())

    def to_bytes(self) -> bytes:
        return self.vec.astype("<u2").tobytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "LtHash":
        if len(data) != VEC_BYTES:
            raise ValueError(f"expected {VEC_BYTES} bytes, got {len(data)}")
        return cls(np.frombuffer(data, dtype="<u2").copy())

    def to_b64(self) -> str:
        return base64.b64encode(self.to_bytes()).decode("ascii")

    @classmethod
    def from_b64(cls, s: str) -> "LtHash":
        return cls.from_bytes(base64.b64decode(s, validate=True))

    def digest(self) -> str:
        return hashlib.blake2b(self.to_bytes(), digest_size=32, person=_PERSON_DIGEST).hexdigest()
