"""Sealed mode: client data stays unreadable after the audit (hybrid post-quantum encryption)."""
from __future__ import annotations

import base64

FIELD_PREFIX = "s:"


class SealError(Exception):
    """Decryption or unwrapping failed: wrong key, wrong context, or tampered data."""


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)
