"""Client key file: hybrid KEM private key encrypted under an Argon2id password key (spec §5.3)."""
from __future__ import annotations

import getpass
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from poi.seal import SealError, b64d, b64e, kem

AAD = b"poi-client-key-v1"
PASSWORD_ENV = "POI_CLIENT_PASSWORD"


class BadPassword(SealError):
    pass


def _kek(password: str, salt: bytes, m_kib: int, t: int, p: int) -> bytes:
    return Argon2id(salt=salt, length=32, iterations=t, lanes=p, memory_cost=m_kib).derive(password.encode("utf-8"))


def pub_path(key_path: Path) -> Path:
    return Path(key_path).with_suffix(".pub")


def create(path: Path, password: str, *, m_kib: int = 65536, t: int = 3, p: int = 4) -> bytes:
    """Write the encrypted key file (0600, never overwritten) and `<name>.pub`. Returns the public key."""
    if not password:
        raise ValueError("empty password")
    sk, pk = kem.generate()
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_kek(password, salt, m_kib, t, p)).encrypt(nonce, sk, AAD)
    doc = {"v": 1, "kdf": "argon2id", "m_kib": m_kib, "t": t, "p": p,
           "salt": b64e(salt), "nonce": b64e(nonce), "ct": b64e(ct), "pub": pk.hex()}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f)
    pub_path(path).write_text(pk.hex() + "\n")
    return pk


def load_private(path: Path, password: str) -> bytes:
    d = json.loads(Path(path).read_text())
    if d.get("v") != 1 or d.get("kdf") != "argon2id":
        raise SealError("unsupported client key file")
    kek = _kek(password, b64d(d["salt"]), d["m_kib"], d["t"], d["p"])
    try:
        return AESGCM(kek).decrypt(b64d(d["nonce"]), b64d(d["ct"]), AAD)
    except InvalidTag:
        raise BadPassword("wrong password") from None


def load_public(path: Path) -> bytes:
    """Accepts `client.pub` (hex line) or the key file itself (its `pub` field)."""
    text = Path(path).read_text().strip()
    pk = bytes.fromhex(json.loads(text)["pub"] if text.startswith("{") else text)
    if len(pk) != kem.PK_LEN:
        raise SealError(f"{path}: not a poi client public key")
    return pk


def get_password(confirm: bool = False) -> str:
    if pw := os.environ.get(PASSWORD_ENV):
        return pw
    pw = getpass.getpass("client key password: ")
    if confirm and getpass.getpass("repeat password: ") != pw:
        raise SealError("passwords do not match")
    return pw
