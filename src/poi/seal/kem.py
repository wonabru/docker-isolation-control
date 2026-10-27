"""Hybrid KEM: ML-KEM-768 + X25519 joined with the X-Wing combiner; key wrapping on top (spec §5.1–5.2)."""
from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from poi.seal import SealError

PK_M, PK_X, CT_M, CT_X, SEED_M = 1184, 32, 1088, 32, 64
PK_LEN, CT_LEN, SK_LEN = PK_M + PK_X, CT_M + CT_X, SEED_M + 32
LABEL = b"\\.//^\\"
_NONCE = bytes(12)          # every wrap uses a fresh KEM secret, so a fixed nonce is safe


def _keys(sk: bytes) -> tuple[MLKEM768PrivateKey, X25519PrivateKey]:
    if len(sk) != SK_LEN:
        raise SealError("bad private key length")
    return MLKEM768PrivateKey.from_seed_bytes(sk[:SEED_M]), X25519PrivateKey.from_private_bytes(sk[SEED_M:])


def generate() -> tuple[bytes, bytes]:
    """Returns (private key, public key)."""
    sk = MLKEM768PrivateKey.generate().private_bytes_raw() + X25519PrivateKey.generate().private_bytes_raw()
    return sk, public_from_private(sk)


def public_from_private(sk: bytes) -> bytes:
    m, x = _keys(sk)
    return m.public_key().public_bytes_raw() + x.public_key().public_bytes_raw()


def _combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + LABEL).digest()


def encaps(pk: bytes) -> tuple[bytes, bytes]:
    """Returns (ciphertext, shared secret)."""
    if len(pk) != PK_LEN:
        raise SealError("bad public key length")
    ss_m, ct_m = MLKEM768PublicKey.from_public_bytes(pk[:PK_M]).encapsulate()
    eph = X25519PrivateKey.generate()
    ct_x = eph.public_key().public_bytes_raw()
    ss_x = eph.exchange(X25519PublicKey.from_public_bytes(pk[PK_M:]))
    return ct_m + ct_x, _combine(ss_m, ss_x, ct_x, pk[PK_M:])


def decaps(sk: bytes, ct: bytes) -> bytes:
    if len(ct) != CT_LEN:
        raise SealError("bad KEM ciphertext length")
    m, x = _keys(sk)
    ss_m = m.decapsulate(ct[:CT_M])          # implicit rejection: a tampered ct gives a wrong secret
    ct_x = ct[CT_M:]
    try:
        ss_x = x.exchange(X25519PublicKey.from_public_bytes(ct_x))
    except ValueError as e:
        raise SealError("bad X25519 share") from e
    return _combine(ss_m, ss_x, ct_x, x.public_key().public_bytes_raw())


def wrap(pk: bytes, key: bytes, aad: bytes) -> bytes:
    ct, ss = encaps(pk)
    return ct + AESGCM(ss).encrypt(_NONCE, key, aad)


def unwrap(sk: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < CT_LEN + 16:
        raise SealError("wrapped key too short")
    try:
        return AESGCM(decaps(sk, blob[:CT_LEN])).decrypt(_NONCE, blob[CT_LEN:], aad)
    except InvalidTag as e:
        raise SealError("unwrap failed: wrong key or context") from e
