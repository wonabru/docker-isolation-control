"""Per-run sealing key EK (spec §5.4): evidence and ledger fields that can carry client data.

Deterministic AES-256-GCM-SIV keeps content-addressed evidence deduplicated and state elements stable;
the cost is that equal values give equal ciphertexts.
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from poi import canonical as c
from poi.seal import FIELD_PREFIX, SealError, b64d, b64e, kem

EV_MAGIC = b"POIEV1"
LOCKED = "🔒"
SEALED_FIELDS = {"egress": {4: "egress.host", 5: "egress.path"},
                 "dns": {3: "dns.name"},
                 "file": {1: "file.path", 6: "file.content"}}
_NONCE = bytes(12)


def _subkey(ek: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ek)


def is_sealed(value: str) -> bool:
    return value.startswith(FIELD_PREFIX)


def display_fields(fields: list[str]) -> list[str]:
    return [LOCKED if is_sealed(x) else x for x in fields]


class Sealer:
    def __init__(self, ek: bytes) -> None:
        if len(ek) != 32:
            raise ValueError("EK must be 32 bytes")
        self._ev = AESGCMSIV(_subkey(ek, b"poi-evidence"))
        self._fld = AESGCMSIV(_subkey(ek, b"poi-field"))

    def seal_evidence(self, data: bytes) -> bytes:
        return EV_MAGIC + self._ev.encrypt(_NONCE, data, b"ev")

    def open_evidence(self, blob: bytes) -> bytes:
        if not blob.startswith(EV_MAGIC):
            return blob                                   # config documents are not sealed
        try:
            return self._ev.decrypt(_NONCE, blob[len(EV_MAGIC):], b"ev")
        except InvalidTag:
            raise SealError("evidence failed authentication (wrong run key?)") from None

    def seal_field(self, name: str, value: str) -> str:
        ct = self._fld.encrypt(_NONCE, value.encode("utf-8"), name.encode())
        return FIELD_PREFIX + base64.urlsafe_b64encode(ct).decode("ascii").rstrip("=")

    def open_field(self, name: str, value: str) -> str:
        if not is_sealed(value):
            return value
        s = value[len(FIELD_PREFIX):]
        try:
            ct = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
            return self._fld.decrypt(_NONCE, ct, name.encode()).decode("utf-8")
        except (InvalidTag, ValueError):
            raise SealError(f"field {name} failed authentication") from None

    def seal_element(self, element: bytes) -> bytes:
        f = c.decode(element)
        for i, name in SEALED_FIELDS.get(f[0], {}).items():
            f[i] = self.seal_field(name, f[i])
        return c.encode(*f)

    def open_fields(self, fields: list[str]) -> list[str]:
        f = list(fields)
        for i, name in SEALED_FIELDS.get(f[0], {}).items():
            if i < len(f):
                f[i] = self.open_field(name, f[i])
        return f


def new_ek() -> bytes:
    return os.urandom(32)


def _ek_aad(run_id: str) -> bytes:
    return b"poi-ek\0" + run_id.encode()


def sealed_doc(ek: bytes, client_pub: bytes, run_id: str, run_pub_raw: bytes) -> bytes:
    """`run/sealed.json`: EK wrapped to the client, plus digests of both public keys."""
    return c.canonical_json({"v": 1, "run_id": run_id, "client_pub": c.b2b256(client_pub),
                             "run_pub": c.b2b256(run_pub_raw),
                             "ek_wrap": b64e(kem.wrap(client_pub, ek, _ek_aad(run_id)))}) + b"\n"


def open_sealed_doc(raw: bytes, client_sk: bytes) -> Sealer:
    try:
        d = json.loads(raw)
        run_id, blob, want = d["run_id"], b64d(d["ek_wrap"]), d["client_pub"]
    except (ValueError, KeyError, TypeError) as e:
        raise SealError(f"malformed sealed.json: {e}") from e
    if want != c.b2b256(kem.public_from_private(client_sk)):
        raise SealError("this run was sealed for a different client key")
    return Sealer(kem.unwrap(client_sk, blob, _ek_aad(run_id)))
