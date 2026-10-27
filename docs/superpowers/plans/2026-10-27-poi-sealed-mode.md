# Tryb `--sealed` — plan implementacji

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Opcjonalny tryb `poi run --sealed`, po którym na hoście zostaje wyłącznie szyfrogram danych klienta (wejście, evidence, pola ledgera, wyjście), odszyfrowywalny tylko kluczem klienta chronionym hasłem.

**Architecture:** Nowy pakiet `poi.seal` (hybrydowy KEM X25519+ML-KEM-768, plik klucza z Argon2id, strumieniowe paczki `*.sealed`, grant do tymczasowego klucza uruchomienia, `Sealer` dla evidence i pól). `poi.sealed_run.SealedSession` prowadzi cykl życia uruchomienia (grant → tmpfs → EK → `out.sealed` → wymazanie). Istniejące moduły dostają opcjonalny `sealer`: WAL i proxy szyfrują, `StateTracker` szyfruje pliki wyjściowe i dopisuje sekcję `sealed` do konfiguracji, a weryfikator, raport, mirror i dashboard odszyfrowują, gdy dostaną klucz klienta.

**Tech Stack:** Python 3.12, `cryptography>=50` (ML-KEM-768, X25519, Argon2id, AES-GCM, AES-GCM-SIV, HKDF), docker-py, pytest.

**Spec:** `docs/superpowers/specs/2026-10-27-poi-sealed-mode-design.md`

## Global Constraints

- Bez nowych zależności; `pyproject.toml`: `"cryptography>=50"`.
- Bez `--sealed` zachowanie i formaty identyczne jak dziś (wszystkie istniejące testy przechodzą bez zmian asercji).
- Kody, komunikaty CLI i komentarze po angielsku (jak reszta kodu); docstringi krótkie, w stylu repo.
- Prefiks pola szyfrowanego: `s:`. Magia evidence: `POIEV1`. Magia paczki: `POISEAL1`. Nowy kod weryfikacji: `E_SEALED = 18`.
- Tag obrazu proxy podbity do `poi-proxy:0.2` (stary obraz nie umie szyfrować).
- Uruchamianie testów: `.venv/bin/pytest -m "not docker" -q` (unit), `.venv/bin/pytest -m "docker and not gpu" -q` (e2e).
- Każdy commit kończy się linią `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Doprecyzowanie względem spec: klucz odcisków (`fp.key`) też przechodzi przez grant (etykieta `fingerprint-key`), więc w trybie sealed operator nie trzyma go na dysku (`--fp-key` zabronione z `--sealed`).

## Mapa plików

| Plik | Odpowiedzialność |
|---|---|
| `src/poi/seal/__init__.py` | `SealError`, `FIELD_PREFIX`, `b64e`/`b64d` |
| `src/poi/seal/kem.py` | Hybrydowy KEM (X-Wing), `wrap`/`unwrap` |
| `src/poi/seal/keyfile.py` | `client.key`/`client.pub`, Argon2id, hasło |
| `src/poi/seal/bundle.py` | Format `*.sealed` (strumieniowy) |
| `src/poi/seal/grant.py` | `RunKey`, `run.pub`, grant, czekanie na grant |
| `src/poi/seal/sealer.py` | `Sealer(EK)`, `sealed.json`, `display_fields` |
| `src/poi/sealed_run.py` | `SealedSession`, `SealedOptions`, swap, `wipe_dir` |
| `src/poi/wal.py`, `proxy_addon.py` | Szyfrowanie zdarzeń w proxy |
| `src/poi/state.py`, `policy.py` | Pliki wyjściowe, sekcja `sealed`, `require_sealed` |
| `src/poi/verify.py`, `report.py` | Odszyfrowanie z kluczem / pominięcie 14 bez klucza |
| `src/poi/runtime.py`, `daemon.py` | Opcje kontenera, sekrety proxy, przebieg sealed |
| `src/poi/cli.py` | Nowe komendy i flagi |
| `src/poi/serve.py`, `source.py`, `mirror.py`, `dashboard.py` | `sealed.json` w feedzie, widoki z kluczem i bez |

---

### Task 1: Pakiet `poi.seal` i hybrydowy KEM

**Files:**
- Create: `src/poi/seal/__init__.py`, `src/poi/seal/kem.py`
- Modify: `pyproject.toml` (`"cryptography>=42"` → `"cryptography>=50"`)
- Test: `tests/test_seal_kem.py`

**Interfaces:**
- Produces: `poi.seal.SealError`, `poi.seal.FIELD_PREFIX = "s:"`, `poi.seal.b64e(bytes)->str`, `poi.seal.b64d(str)->bytes`; `kem.generate()->(sk 96 B, pk 1216 B)`, `kem.public_from_private(sk)->pk`, `kem.encaps(pk)->(ct 1120 B, ss 32 B)`, `kem.decaps(sk, ct)->ss`, `kem.wrap(pk, key, aad)->bytes`, `kem.unwrap(sk, blob, aad)->bytes`; stałe `PK_LEN`, `CT_LEN`, `SK_LEN`, `CT_M`.

- [ ] **Step 1: Write the failing test** — `tests/test_seal_kem.py`

```python
import pytest

from poi.seal import SealError, kem


def test_sizes_and_roundtrip():
    sk, pk = kem.generate()
    assert (len(sk), len(pk)) == (kem.SK_LEN, kem.PK_LEN) == (96, 1216)
    assert kem.public_from_private(sk) == pk
    ct, ss = kem.encaps(pk)
    assert len(ct) == kem.CT_LEN == 1120 and kem.decaps(sk, ct) == ss
    blob = kem.wrap(pk, b"k" * 32, b"ctx")
    assert kem.unwrap(sk, blob, b"ctx") == b"k" * 32


@pytest.mark.parametrize("pos", [0, kem.CT_M - 1, kem.CT_M, kem.CT_LEN - 1, kem.CT_LEN])
def test_tampering_rejected(pos):          # ML-KEM part, X25519 part, AEAD part
    sk, pk = kem.generate()
    blob = bytearray(kem.wrap(pk, b"k" * 32, b"ctx"))
    blob[pos] ^= 1
    with pytest.raises(SealError):
        kem.unwrap(sk, bytes(blob), b"ctx")


def test_wrong_context_or_key_rejected():
    sk, pk = kem.generate()
    other, _ = kem.generate()
    blob = kem.wrap(pk, b"k" * 32, b"ctx")
    with pytest.raises(SealError):
        kem.unwrap(sk, blob, b"other")
    with pytest.raises(SealError):
        kem.unwrap(other, blob, b"ctx")
    with pytest.raises(SealError):
        kem.unwrap(sk, blob[:100], b"ctx")
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_seal_kem.py -q` — Expected: FAIL (`ModuleNotFoundError: poi.seal`).

- [ ] **Step 3: Implement** — `src/poi/seal/__init__.py`

```python
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
```

`src/poi/seal/kem.py`

```python
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
```

- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_seal_kem.py -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/seal pyproject.toml tests/test_seal_kem.py
git commit -m "feat(seal): hybrid X25519+ML-KEM-768 KEM with key wrapping

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Plik klucza klienta

**Files:**
- Create: `src/poi/seal/keyfile.py`
- Modify: `tests/helpers.py` (dopisać `FAST_KDF = {"m_kib": 1024, "t": 1, "p": 1}`)
- Test: `tests/test_seal_keyfile.py`

**Interfaces:**
- Consumes: `kem.generate`, `kem.PK_LEN`, `SealError`, `b64e`, `b64d`.
- Produces: `keyfile.create(path, password, *, m_kib=65536, t=3, p=4) -> bytes(pk)` (pisze `path` 0600 i `pub_path(path)`), `keyfile.pub_path(path)->Path` (`client.key`→`client.pub`), `keyfile.load_private(path, password)->bytes`, `keyfile.load_public(path)->bytes` (przyjmuje `.pub` lub `.key`), `keyfile.get_password(confirm=False)->str`, `keyfile.BadPassword(SealError)`, `keyfile.PASSWORD_ENV = "POI_CLIENT_PASSWORD"`.

- [ ] **Step 1: Write the failing test** — `tests/test_seal_keyfile.py`

```python
import pytest

from poi.seal import kem, keyfile

from helpers import FAST_KDF


def test_create_and_load(tmp_path):
    path = tmp_path / "client.key"
    pk = keyfile.create(path, "hasło", **FAST_KDF)
    assert (tmp_path / "client.pub").read_text().strip() == pk.hex()
    assert path.stat().st_mode & 0o777 == 0o600
    sk = keyfile.load_private(path, "hasło")
    assert kem.public_from_private(sk) == pk
    assert keyfile.load_public(tmp_path / "client.pub") == pk == keyfile.load_public(path)


def test_wrong_password(tmp_path):
    keyfile.create(tmp_path / "client.key", "good", **FAST_KDF)
    with pytest.raises(keyfile.BadPassword):
        keyfile.load_private(tmp_path / "client.key", "bad")


def test_refuses_to_overwrite(tmp_path):
    keyfile.create(tmp_path / "client.key", "pw", **FAST_KDF)
    with pytest.raises(FileExistsError):
        keyfile.create(tmp_path / "client.key", "pw", **FAST_KDF)


def test_password_from_env(monkeypatch):
    monkeypatch.setenv(keyfile.PASSWORD_ENV, "x")
    assert keyfile.get_password() == "x"
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_seal_keyfile.py -q` — Expected: FAIL (brak modułu / `FAST_KDF`).

- [ ] **Step 3: Implement** — dopisać na końcu `tests/helpers.py`:

```python
FAST_KDF = {"m_kib": 1024, "t": 1, "p": 1}       # Argon2id parameters that keep tests fast
```

`src/poi/seal/keyfile.py`

```python
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
```

- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_seal_keyfile.py -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/seal/keyfile.py tests/helpers.py tests/test_seal_keyfile.py
git commit -m "feat(seal): password-protected client key file (Argon2id)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 3: Paczka `*.sealed`

**Files:**
- Create: `src/poi/seal/bundle.py`
- Test: `tests/test_seal_bundle.py`

**Interfaces:**
- Consumes: `kem.wrap/unwrap`, `canonical.canonical_json`, `SealError`, `b64e/b64d`.
- Produces: `bundle.seal_dir(src, out, recipient_pub, kind="data", chunk=CHUNK) -> str` (digest pliku), `bundle.file_digest(path) -> str` (= `b2b256` całego pliku), `bundle.header_of(path) -> Header`, `bundle.dek_for(path, client_sk) -> bytes`, `bundle.unseal_to(path, dek, dest) -> None`; stałe `MAGIC = b"POISEAL1"`, `CHUNK = 1 << 20`, `TAG = 16`.

- [ ] **Step 1: Write the failing test** — `tests/test_seal_bundle.py`

```python
import os
import struct

import pytest

from poi.seal import SealError, bundle, kem


@pytest.fixture
def keys():
    return kem.generate()


def _tree(root):
    return {str(p.relative_to(root)): (p.read_bytes() if p.is_file() else None) for p in sorted(root.rglob("*"))}


def _src(tmp_path, size=5000):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "a.csv").write_bytes(os.urandom(size))
    (src / "sub" / "b.txt").write_bytes(b"hello patient 85010112345")
    return src


def _split(path):
    raw = path.read_bytes()
    n = struct.unpack(">I", raw[8:12])[0]
    return raw[:12 + n], raw[12 + n:]


def _unseal(path, sk, dest):
    bundle.unseal_to(path, bundle.dek_for(path, sk), dest)


def test_roundtrip_multi_chunk(tmp_path, keys):
    sk, pk = keys
    src = _src(tmp_path)
    p = tmp_path / "d.sealed"
    d = bundle.seal_dir(src, p, pk, chunk=1024)
    assert d == bundle.file_digest(p)
    raw = p.read_bytes()
    assert raw.startswith(bundle.MAGIC) and b"85010112345" not in raw
    assert len(_split(p)[1]) > 3 * (1024 + bundle.TAG)
    _unseal(p, sk, tmp_path / "out")
    assert _tree(tmp_path / "out") == _tree(src)


def test_empty_dir(tmp_path, keys):
    sk, pk = keys
    (tmp_path / "e").mkdir()
    bundle.seal_dir(tmp_path / "e", tmp_path / "e.sealed", pk)
    _unseal(tmp_path / "e.sealed", sk, tmp_path / "out")
    assert _tree(tmp_path / "out") == {}


def test_truncation_detected(tmp_path, keys):
    sk, pk = keys
    p = tmp_path / "d.sealed"
    bundle.seal_dir(_src(tmp_path), p, pk, chunk=1024)
    head, body = _split(p)
    step = 1024 + bundle.TAG
    p.write_bytes(head + body[: (len(body) - 1) // step * step])     # drop the final chunk
    with pytest.raises(SealError):
        _unseal(p, sk, tmp_path / "out")


def test_swapped_chunks_detected(tmp_path, keys):
    sk, pk = keys
    p = tmp_path / "d.sealed"
    bundle.seal_dir(_src(tmp_path), p, pk, chunk=1024)
    head, body = _split(p)
    step = 1024 + bundle.TAG
    p.write_bytes(head + body[step:2 * step] + body[:step] + body[2 * step:])
    with pytest.raises(SealError):
        _unseal(p, sk, tmp_path / "out")


def test_header_is_authenticated(tmp_path, keys):
    sk, pk = keys
    p = tmp_path / "d.sealed"
    bundle.seal_dir(_src(tmp_path), p, pk, chunk=1024)
    p.write_bytes(p.read_bytes().replace(b'"kind":"data"', b'"kind":"datx"', 1))
    with pytest.raises(SealError):
        _unseal(p, sk, tmp_path / "out")


def test_wrong_key_and_not_a_bundle(tmp_path, keys):
    _, pk = keys
    other, _ = kem.generate()
    p = tmp_path / "d.sealed"
    bundle.seal_dir(_src(tmp_path), p, pk)
    with pytest.raises(SealError):
        bundle.dek_for(p, other)
    (tmp_path / "x").write_bytes(b"hello")
    with pytest.raises(SealError):
        bundle.header_of(tmp_path / "x")
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_seal_bundle.py -q` — Expected: FAIL (brak `bundle`).

- [ ] **Step 3: Implement** — `src/poi/seal/bundle.py`

```python
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
```

- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_seal_bundle.py -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/seal/bundle.py tests/test_seal_bundle.py
git commit -m "feat(seal): streaming sealed bundle format

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Klucz uruchomienia i grant

**Files:**
- Create: `src/poi/seal/grant.py`
- Test: `tests/test_seal_grant.py`

**Interfaces:**
- Consumes: `kem`, `canonical.canonical_json/b2b256`, `SealError`, `b64e/b64d`.
- Produces: `RunKey(run_id, sk, pk)` z `RunKey.generate(run_id)` i `.pub_bytes() -> bytes` (zawartość `run.pub`); `read_run_pub(raw) -> (run_id, pk)`; `make_grant(run_pub_raw, keys: dict[str, bytes]) -> bytes`; `open_grant(raw, rk) -> dict[str, bytes]`; `bundle_label(digest) -> "bundle:<digest>"`; `FP_LABEL = "fingerprint-key"`; `wait_for_grant(path, rk, needed: set[str], timeout, poll=0.5, *, sleep=time.sleep, monotonic=time.monotonic) -> dict[str, bytes]`.

- [ ] **Step 1: Write the failing test** — `tests/test_seal_grant.py`

```python
import json

import pytest

from poi.seal import SealError, b64d, b64e
from poi.seal.grant import (FP_LABEL, RunKey, bundle_label, make_grant, open_grant, read_run_pub,
                            wait_for_grant)


def test_roundtrip():
    rk = RunKey.generate("r1")
    assert read_run_pub(rk.pub_bytes()) == ("r1", rk.pk)
    keys = {bundle_label("d" * 64): b"k" * 32, FP_LABEL: b"f" * 32}
    assert open_grant(make_grant(rk.pub_bytes(), keys), rk) == keys


def test_other_run_rejected():
    g = make_grant(RunKey.generate("r1").pub_bytes(), {"bundle:x": b"k" * 32})
    with pytest.raises(SealError):
        open_grant(g, RunKey.generate("r2"))
    with pytest.raises(SealError):                  # same id, different (fresh) run key
        open_grant(g, RunKey.generate("r1"))


def test_relabelled_key_rejected():
    rk = RunKey.generate("r1")
    d = json.loads(make_grant(rk.pub_bytes(), {"bundle:a": b"k" * 32}))
    d["keys"] = {"bundle:b": d["keys"]["bundle:a"]}
    with pytest.raises(SealError):
        open_grant(json.dumps(d).encode(), rk)


def test_garbage_rejected():
    with pytest.raises(SealError):
        open_grant(b"not json", RunKey.generate("r1"))
    with pytest.raises(SealError):
        open_grant(json.dumps({"v": 1, "run_id": "r1", "keys": {"a": b64e(b"x")}}).encode(),
                   RunKey.generate("r1"))
    assert b64d(b64e(b"x")) == b"x"


def _clock():
    t = [0.0]

    def sleep(s):
        t[0] += s
    return t, sleep, (lambda: t[0])


def test_wait_skips_bad_grant_then_accepts(tmp_path):
    rk = RunKey.generate("r1")
    path = tmp_path / "grant.bin"
    path.write_bytes(make_grant(RunKey.generate("r1").pub_bytes(), {"bundle:x": b"k" * 32}))
    t, base_sleep, mono = _clock()

    def sleep(s):
        base_sleep(s)
        if t[0] >= 1:
            path.write_bytes(make_grant(rk.pub_bytes(), {"bundle:x": b"k" * 32}))
    assert wait_for_grant(path, rk, {"bundle:x"}, 10, sleep=sleep, monotonic=mono) == {"bundle:x": b"k" * 32}


def test_wait_times_out_without_grant_or_with_missing_key(tmp_path):
    rk = RunKey.generate("r1")
    _, sleep, mono = _clock()
    with pytest.raises(SealError, match="no valid grant"):
        wait_for_grant(tmp_path / "grant.bin", rk, {"bundle:x"}, 3, sleep=sleep, monotonic=mono)
    (tmp_path / "grant.bin").write_bytes(make_grant(rk.pub_bytes(), {"bundle:x": b"k" * 32}))
    _, sleep, mono = _clock()
    with pytest.raises(SealError):
        wait_for_grant(tmp_path / "grant.bin", rk, {"bundle:x", FP_LABEL}, 3, sleep=sleep, monotonic=mono)
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_seal_grant.py -q` — Expected: FAIL.

- [ ] **Step 3: Implement** — `src/poi/seal/grant.py`

```python
"""Run key and grant (spec §5.6): the client wraps data keys to a key that exists only in RAM during the run."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from poi import canonical as c
from poi.seal import SealError, b64d, b64e, kem

log = logging.getLogger("poi")
FP_LABEL = "fingerprint-key"


def bundle_label(digest: str) -> str:
    return f"bundle:{digest}"


def _aad(run_id: str, label: str) -> bytes:
    return f"poi-grant\0{run_id}\0{label}".encode()


@dataclass
class RunKey:
    run_id: str
    sk: bytes
    pk: bytes

    @classmethod
    def generate(cls, run_id: str) -> "RunKey":
        sk, pk = kem.generate()
        return cls(run_id, sk, pk)

    def pub_bytes(self) -> bytes:
        return c.canonical_json({"run_id": self.run_id, "pub": self.pk.hex()}) + b"\n"


def read_run_pub(raw: bytes) -> tuple[str, bytes]:
    try:
        d = json.loads(raw)
        return d["run_id"], bytes.fromhex(d["pub"])
    except (ValueError, KeyError, TypeError) as e:
        raise SealError(f"malformed run.pub: {e}") from e


def make_grant(run_pub_raw: bytes, keys: dict[str, bytes]) -> bytes:
    run_id, pk = read_run_pub(run_pub_raw)
    wrapped = {label: b64e(kem.wrap(pk, key, _aad(run_id, label))) for label, key in sorted(keys.items())}
    return c.canonical_json({"v": 1, "run_id": run_id, "keys": wrapped}) + b"\n"


def open_grant(raw: bytes, rk: RunKey) -> dict[str, bytes]:
    try:
        d = json.loads(raw)
        run_id, items = d["run_id"], dict(d["keys"])
    except (ValueError, KeyError, TypeError) as e:
        raise SealError(f"malformed grant: {e}") from e
    if run_id != rk.run_id:
        raise SealError(f"grant is for run {run_id}, this is run {rk.run_id}")
    try:
        return {label: kem.unwrap(rk.sk, b64d(v), _aad(run_id, label)) for label, v in items.items()}
    except (ValueError, TypeError) as e:
        raise SealError(f"malformed grant: {e}") from e


def wait_for_grant(path: Path, rk: RunKey, needed: set[str], timeout: float, poll: float = 0.5, *,
                   sleep: Callable[[float], None] = time.sleep,
                   monotonic: Callable[[], float] = time.monotonic) -> dict[str, bytes]:
    """Poll `path` until a grant that opens and holds every `needed` key appears. Bad grants are skipped."""
    deadline = monotonic() + timeout
    rejected: set[str] = set()
    while True:
        try:
            raw = Path(path).read_bytes()
        except FileNotFoundError:
            raw = None
        if raw is not None and (d := c.b2b256(raw)) not in rejected:
            try:
                keys = open_grant(raw, rk)
                missing = needed - keys.keys()
                if not missing:
                    return keys
                log.warning("grant rejected: no key for %s", sorted(missing))
            except SealError as e:
                log.warning("grant rejected: %s", e)
            rejected.add(d)
        if monotonic() >= deadline:
            raise SealError(f"no valid grant in {path} within {timeout:g} s")
        sleep(poll)
```

- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_seal_grant.py -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/seal/grant.py tests/test_seal_grant.py
git commit -m "feat(seal): per-run key and client grant

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 5: `Sealer` i `sealed.json`

**Files:**
- Create: `src/poi/seal/sealer.py`
- Test: `tests/test_seal_sealer.py`

**Interfaces:**
- Consumes: `kem.wrap/unwrap/public_from_private`, `canonical`, `SealError`, `FIELD_PREFIX`.
- Produces: `Sealer(ek: bytes)` z metodami `seal_evidence(bytes)->bytes`, `open_evidence(bytes)->bytes` (dane bez `EV_MAGIC` zwraca bez zmian), `seal_field(name, str)->str`, `open_field(name, str)->str`, `seal_element(bytes)->bytes`, `open_fields(list[str])->list[str]`; `is_sealed(str)->bool`; `display_fields(list[str])->list[str]` (pola `s:` → `LOCKED`); `new_ek()->bytes`; `sealed_doc(ek, client_pub, run_id, run_pub_raw)->bytes`; `open_sealed_doc(raw, client_sk)->Sealer`; stałe `EV_MAGIC = b"POIEV1"`, `LOCKED = "🔒"`, `SEALED_FIELDS`.

Pola szyfrowane (indeksy w `canonical.decode(element)`): `egress` 4 (host), 5 (path); `dns` 3 (name); `file` 1 (path), 6 (content). Inne domeny (`ingress`, `config`) bez zmian.

- [ ] **Step 1: Write the failing test** — `tests/test_seal_sealer.py`

```python
import json

import pytest

from poi import canonical as c
from poi.seal import SealError, kem
from poi.seal.sealer import (EV_MAGIC, LOCKED, Sealer, display_fields, is_sealed, open_sealed_doc,
                             sealed_doc)

T = "2026-10-27T10:00:00Z"
S = Sealer(b"e" * 32)


def test_evidence_deterministic_roundtrip():
    a = S.seal_evidence(b"pesel 85010112345")
    assert a == S.seal_evidence(b"pesel 85010112345") and a.startswith(EV_MAGIC) and b"85010112345" not in a
    assert S.open_evidence(a) == b"pesel 85010112345"
    assert S.open_evidence(S.seal_evidence(b"")) == b""
    assert S.open_evidence(b'{"plain":"config"}') == b'{"plain":"config"}'
    with pytest.raises(SealError):
        Sealer(b"x" * 32).open_evidence(a)


def test_egress_element_sealed_in_place():
    el = c.egress_element(1, T, "POST", "evil.test", "/c/85010112345", "h" * 64, "b" * 64, "block", "host-not-allowed")
    sealed = S.seal_element(el)
    f = c.decode(sealed)
    assert len(f) == len(c.decode(el)) and is_sealed(f[4]) and is_sealed(f[5])
    assert (f[3], f[6], f[7], f[8], f[9]) == ("POST", "h" * 64, "b" * 64, "block", "host-not-allowed")
    assert b"85010112345" not in sealed and b"evil" not in sealed
    assert S.seal_element(el) == sealed
    assert S.open_fields(f) == c.decode(el)


def test_dns_file_and_untouched_domains():
    dns = c.dns_element(2, T, "85010112345.evil.test", "A", "block")
    assert is_sealed(c.decode(S.seal_element(dns))[3])
    fe = c.file_element("/srv/out/r.json", "file", 0o644, 0, 0, "d" * 64)
    f = c.decode(S.seal_element(fe))
    assert is_sealed(f[1]) and is_sealed(f[6]) and f[2] == "file"
    assert S.open_fields(f) == c.decode(fe)
    for el in (c.ingress_element(1, 200, "h" * 64, "b" * 64), c.config_element("c" * 64)):
        assert S.seal_element(el) == el


def test_field_name_is_bound():
    v = S.seal_field("egress.host", "evil.test")
    with pytest.raises(SealError):
        S.open_field("egress.path", v)
    assert S.open_field("egress.path", "/plain") == "/plain"


def test_display_fields():
    f = c.decode(S.seal_element(c.dns_element(2, T, "x.evil.test", "A", "block")))
    assert display_fields(f)[3] == LOCKED and display_fields(f)[5] == "block"


def test_sealed_doc():
    sk, pk = kem.generate()
    raw = sealed_doc(b"e" * 32, pk, "r1", b"run-pub")
    d = json.loads(raw)
    assert (d["run_id"], d["client_pub"], d["run_pub"]) == ("r1", c.b2b256(pk), c.b2b256(b"run-pub"))
    assert open_sealed_doc(raw, sk).open_evidence(S.seal_evidence(b"x")) == b"x"
    other, _ = kem.generate()
    with pytest.raises(SealError):
        open_sealed_doc(raw, other)
    with pytest.raises(SealError):
        open_sealed_doc(b"{}", sk)
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_seal_sealer.py -q` — Expected: FAIL.

- [ ] **Step 3: Implement** — `src/poi/seal/sealer.py`

```python
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
```

- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_seal_sealer.py -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/seal/sealer.py tests/test_seal_sealer.py
git commit -m "feat(seal): run key sealer for evidence and ledger fields

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Szyfrowanie w WAL i w proxy

**Files:**
- Modify: `src/poi/wal.py` (`WalWriter.__init__`, `record_egress`, `record_dns`, `record_ingress`)
- Modify: `src/poi/proxy_addon.py` (`PoiAddon.__init__`)
- Modify: `src/poi/runtime.py:16` (`PROXY_IMAGE = "poi-proxy:0.2"`), `README.md` (dwa wystąpienia `poi-proxy:0.1` → `poi-proxy:0.2`)
- Test: `tests/test_wal.py` (nowy test)

**Interfaces:**
- Consumes: `Sealer.seal_evidence`, `Sealer.seal_element`.
- Produces: `WalWriter(wal_dir, evidence_dir, sealer=None)`; w proxy katalog sekretów `/run/poi-secrets` (`ek`, `fingerprint.key`), zmienna `POI_SECRETS`.

- [ ] **Step 1: Write the failing test** — dopisać do `tests/test_wal.py`:

```python
def test_sealed_writer_keeps_client_data_out_of_files(tmp_path):
    from poi.seal.sealer import Sealer
    s = Sealer(b"e" * 32)
    w = WalWriter(tmp_path / "wal", tmp_path / "evidence", sealer=s)
    seq = w.record_egress(T, "POST", "evil.test", "/c/85010112345", [("x-covert", "85010112345")],
                          b'{"pesel":"85010112345"}', "block", "host-not-allowed")
    w.record_dns(T, "85010112345.evil.test", "A", "block")
    w.record_ingress(seq, 200, [], b"85010112345")
    for p in [w.path, *(tmp_path / "evidence").iterdir()]:
        assert b"85010112345" not in p.read_bytes()
    entries = WalReader(tmp_path / "wal").read_new()
    assert all(b"85010112345" not in e.element for e in entries)
    f = s.open_fields(c.decode(entries[0].element))
    assert (f[4], f[5]) == ("evil.test", "/c/85010112345")
    assert s.open_evidence(evidence.get(tmp_path / "evidence", f[7])) == b'{"pesel":"85010112345"}'
    assert s.open_fields(c.decode(entries[1].element))[3] == "85010112345.evil.test"
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_wal.py -q` — Expected: FAIL (`unexpected keyword argument 'sealer'`).

- [ ] **Step 3: Implement** — w `src/poi/wal.py` zmienić `WalWriter`:

```python
class WalWriter:
    """Thread-safe; shared by the HTTP addon and the DNS stub so `seq` is one counter.

    With a `sealer` (sealed mode) evidence and client-data fields are encrypted before they are written.
    """

    def __init__(self, wal_dir: Path, evidence_dir: Path, sealer=None) -> None:
        self.path = Path(wal_dir) / WAL_NAME
        self.evidence_dir = Path(evidence_dir)
        self.sealer = sealer
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.seq = self._recover()

    def _put(self, data: bytes) -> str:
        return evidence.put(self.evidence_dir, self.sealer.seal_evidence(data) if self.sealer else data)

    def _el(self, element: bytes) -> bytes:
        return self.sealer.seal_element(element) if self.sealer else element
```

(`_recover` i `_append` bez zmian.) Metody zapisu:

```python
    def record_egress(self, t: str, method: str, host: str, path: str,
                      headers: list[tuple[str, str]], body: bytes, verdict: str, reason: str) -> int:
        """Store evidence, then append the element. Raises OSError on failure: caller must block."""
        hd = self._put(_norm_headers(headers))
        bd = self._put(body)
        with self._lock:
            seq = self.seq + 1
            self._append("egress", seq, self._el(c.egress_element(seq, t, method, host, path, hd, bd, verdict, reason)))
            self.seq = seq
        return seq

    def record_dns(self, t: str, name: str, qtype: str, verdict: str) -> int:
        with self._lock:
            seq = self.seq + 1
            self._append("dns", seq, self._el(c.dns_element(seq, t, name, qtype, verdict)))
            self.seq = seq
        return seq

    def record_ingress(self, seq: int, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        hd = self._put(_norm_headers(headers))
        bd = self._put(body)
        with self._lock:
            self._append("ingress", seq, c.ingress_element(seq, status, hd, bd))
```

W `src/poi/proxy_addon.py`:

```python
RUN = Path(os.environ.get("POI_RUN", "/run/poi"))
SECRETS = Path(os.environ.get("POI_SECRETS", "/run/poi-secrets"))   # sealed mode: tmpfs, read-only


class PoiAddon:
    def __init__(self) -> None:
        self.policy = pol.load(RUN / "policy.yaml")
        sealer = None
        if (SECRETS / "ek").exists():
            from poi.seal.sealer import Sealer
            sealer = Sealer((SECRETS / "ek").read_bytes())
        self.wal = WalWriter(RUN / "proxy-wal", RUN / "evidence", sealer)
        fp = None
        if (RUN / "fingerprints.bin").exists():
            kp = SECRETS / "fingerprint.key" if (SECRETS / "fingerprint.key").exists() else RUN / "fingerprint.key"
            fp = FingerprintSet.load(RUN / "fingerprints.bin", kp.read_bytes(),
                                     self.policy.fingerprint_k, self.policy.fingerprint_w)
        self.gate = EgressGate(self.policy, self.wal, fp)
        self.dns = start_dns(self.wal, self.policy.hosts, os.environ["POI_PROXY_IP"])
```

W `src/poi/runtime.py` zmienić `PROXY_IMAGE = "poi-proxy:0.2"` i dodać pod nim:

```python
SECRETS_IN_PROXY = "/run/poi-secrets"     # must match POI_SECRETS in proxy_addon.py
```

W `README.md` zamienić oba `poi-proxy:0.1` na `poi-proxy:0.2`.

- [ ] **Step 4: Run** `.venv/bin/pytest -m "not docker" -q` — Expected: PASS (cały zestaw unit).

- [ ] **Step 5: Commit**

```bash
git add src/poi/wal.py src/poi/proxy_addon.py src/poi/runtime.py README.md tests/test_wal.py
git commit -m "feat(seal): proxy seals evidence and client-data fields; proxy image 0.2

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 7: `StateTracker` w trybie sealed i `require_sealed` w polityce

**Files:**
- Modify: `src/poi/state.py` (`StateTracker.__init__`, `_excludes`, `_config`, `target`; nowa funkcja `sealed_section`)
- Modify: `src/poi/policy.py` (`Policy.require_sealed`, `parse`, `config_violations`)
- Test: `tests/test_state_sealed.py`

**Interfaces:**
- Consumes: `Sealer.seal_element`.
- Produces: `StateTracker(fs, output=None, retries=3, image_mode="files", attest_mounts=(), sealer=None, sealed_info: dict | None = None)`; `state.sealed_section(inspect, info) -> dict`; `Policy.require_sealed: bool`. Sekcja `sealed` w dokumencie konfiguracji = `info` + `rootfs_ro`, `log_driver`, `tmpfs` odczytane z `docker inspect` (nie deklarowane). Ścieżki tmpfs są wyłączone ze skanu stanu.

- [ ] **Step 1: Write the failing test** — `tests/test_state_sealed.py`

```python
import json

from poi import canonical as c
from poi.policy import config_violations, parse
from poi.seal.sealer import Sealer, is_sealed
from poi.state import StateTracker, config_doc

from helpers import ENGINE_IMAGE, ENGINE_MOUNTS, POLICY, FakeFS

INFO = {"client_pub": "c" * 64, "run_pub": "r" * 64, "mounts": {"/data": "d" * 64}, "swap": False,
        "out_target": "/srv/out"}
SEALED_HC = {"ReadonlyRootfs": True, "LogConfig": {"Type": "none"}, "Tmpfs": {"/tmp": ""}}


def test_output_sealed_config_section_and_tmpfs_excluded(tmp_path):
    fs = FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS)
    fs.host_extra = SEALED_HC
    fs.write("/tmp", None)
    fs.write("/tmp/scratch", b"85010112345")
    out = tmp_path / "out"
    out.mkdir()
    (out / "result.json").write_bytes(b"85010112345")
    s = Sealer(b"e" * 32)
    tr = StateTracker(fs, (out, "/srv/out"), sealer=s, sealed_info=INFO)
    t = tr.target(full=True)
    assert "/tmp/scratch" not in t and "/tmp" not in t
    el = t["/srv/out/result.json"]
    assert b"result.json" not in el and is_sealed(c.decode(el)[1])
    assert s.open_fields(c.decode(el))[1] == "/srv/out/result.json"
    doc = json.loads(tr.last_config)
    assert doc["sealed"] == {**INFO, "rootfs_ro": True, "log_driver": "none", "tmpfs": ["/tmp"]}
    assert tr.update(full=True) and tr.update(full=True) == []     # deterministic: no churn between scans


def test_unsealed_tracker_unchanged(tmp_path):
    tr = StateTracker(FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS), (tmp_path, "/srv/out"))
    tr.target()
    assert "sealed" not in json.loads(tr.last_config)


def _sealed_violations(doc, policy):
    return [v for v in config_violations(doc, policy) if v.startswith("sealed")]


def test_require_sealed():
    fs = FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS)
    doc = config_doc(fs.inspect(), fs.network_internal)
    plain = parse(POLICY)
    strict = parse(POLICY + b"require_sealed: true\n")
    assert not plain.require_sealed and strict.require_sealed
    assert config_violations(doc, plain) == []
    assert _sealed_violations(doc, strict) == ["sealed mode required but the run is not sealed"]
    good = {**INFO, "rootfs_ro": True, "log_driver": "none", "tmpfs": ["/tmp"]}
    assert _sealed_violations({**doc, "sealed": good}, strict) == []
    for bad in ({"rootfs_ro": False}, {"log_driver": "json-file"}, {"swap": True}):
        assert len(_sealed_violations({**doc, "sealed": {**good, **bad}}, strict)) == 1
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_state_sealed.py -q` — Expected: FAIL.

- [ ] **Step 3: Implement** — w `src/poi/state.py` dodać po `config_doc`:

```python
def sealed_section(inspect: dict, info: dict) -> dict:
    """Sealed-mode facts: `info` from the run plus what Docker reports about the container (spec §7)."""
    hc = inspect["HostConfig"]
    return {**info, "rootfs_ro": bool(hc.get("ReadonlyRootfs")),
            "log_driver": (hc.get("LogConfig") or {}).get("Type", ""),
            "tmpfs": sorted((hc.get("Tmpfs") or {}).keys())}
```

W `StateTracker`:

```python
    def __init__(self, fs: ContainerFS, output: tuple[Path, str] | None = None,
                 retries: int = 3, image_mode: str = "files", attest_mounts: tuple[str, ...] = (),
                 sealer=None, sealed_info: dict | None = None) -> None:
        ...  # dotychczasowe przypisania bez zmian, a na końcu:
        self.sealer = sealer
        self.sealed_info = sealed_info

    def _excludes(self, inspect: dict) -> tuple[str, ...]:
        tmpfs = (inspect.get("HostConfig") or {}).get("Tmpfs") or {}
        return tuple(sorted({m["Destination"] for m in inspect.get("Mounts", [])} | set(tmpfs)))

    def _config(self, inspect: dict) -> tuple[str, bytes]:
        doc = config_doc(inspect, self.fs.network_internal, self._mount_content(inspect))
        if self.sealed_info is not None:
            doc["sealed"] = sealed_section(inspect, self.sealed_info)
        raw = config_bytes(doc)
        self.last_config = raw
        return c.b2b256(raw), c.config_element(c.b2b256(raw))
```

W `target` zamienić blok `if self.output is not None:` na:

```python
        if self.output is not None:
            out = scan_host_dir(*self.output)
            if self.sealer is not None:          # output file names and digests are client data
                out = {k: self.sealer.seal_element(v) for k, v in out.items()}
            t.update(out)
```

W `src/poi/policy.py`: pole `require_sealed: bool = False` w `Policy` (po `attest_mounts`), w `parse` argument `require_sealed=bool(d.get("require_sealed", False))`, a na końcu `config_violations` przed `return v`:

```python
    if policy.require_sealed:
        s = doc.get("sealed")
        if not isinstance(s, dict):
            v.append("sealed mode required but the run is not sealed")
        else:
            if s.get("rootfs_ro") is not True:
                v.append("sealed: root filesystem must be read-only")
            if s.get("log_driver") != "none":
                v.append("sealed: container logs must be disabled (log driver none)")
            if s.get("swap") is not False:
                v.append("sealed: swap was active during the run")
```

(Zapisywalne montaże inne niż `output_volume` już zgłasza istniejąca reguła; tmpfs nie występują w `Mounts`.)

- [ ] **Step 4: Run** `.venv/bin/pytest -m "not docker" -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/state.py src/poi/policy.py tests/test_state_sealed.py
git commit -m "feat(seal): sealed output elements, sealed config section, require_sealed policy

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Weryfikator z kluczem klienta i bez niego

**Files:**
- Modify: `src/poi/verify.py` (stała `E_SEALED`, `VerifyResult.sealed_unchecked`, `_check_egress`, `ChainVerifier`, `verify_policy`, `verify_run`)
- Modify: `tests/helpers.py` (`make_engine(..., sealer=None)`, nowe `SEALED_EK`, `make_sealed_run`)
- Modify: `tests/test_verify_independence.py` (`ALLOWED` += `"poi.seal"`)
- Test: `tests/test_verify_sealed.py`

**Interfaces:**
- Consumes: `poi.seal.SealError`, `poi.seal.FIELD_PREFIX`; obiekt z `open_fields`/`open_evidence` (`Sealer`).
- Produces: `E_SEALED = 18`; `VerifyResult.sealed_unchecked: int`; `ChainVerifier(pubkey_hex, policy=None, sealer=None)`; `verify_policy(res, run_dir, policy, sealer=None)`; `verify_run(run_dir, pubkey_hex, policy, sealer=None)`; w helpers `SEALED_EK = b"e" * 32` i `make_sealed_run(tmp_path, key, client_pub=None) -> (run_dir, sealer, client_sk | None)` (1 dozwolone żądanie z odpowiedzią, 1 zablokowane `POST evil.test/c/85010112345` z treścią `DASH_SECRET`, 1 zablokowany DNS `85010112345.evil.test`, plik wyjściowy `/srv/out/r.txt`, `run/sealed.json`).

- [ ] **Step 1: Write the failing test** — najpierw helpers. W `tests/helpers.py` zmienić `make_engine`:

```python
def make_engine(tmp_path, key, fs, violations=None, sealer=None):
    """Engine + EgressGate over a FakeFS, writing a run into tmp_path/run."""
    ...  # importy bez zmian
    eng = Engine(Ledger(tmp_path / "run", key), StateTracker(fs, (out, "/srv/out"), sealer=sealer),
                 ...)  # reszta argumentów bez zmian
    gate = EgressGate(pol, WalWriter(tmp_path / "run" / "proxy-wal", tmp_path / "run" / "evidence", sealer))
    return eng, gate
```

i dopisać na końcu pliku:

```python
SEALED_EK = b"e" * 32


def make_sealed_run(tmp_path, key, client_pub=None):
    """Sealed run over a FakeFS. Returns (run_dir, sealer, client_sk or None when client_pub was given)."""
    from poi.seal import kem
    from poi.seal.sealer import Sealer, sealed_doc

    client_sk = None
    if client_pub is None:
        client_sk, client_pub = kem.generate()
    s = Sealer(SEALED_EK)
    eng, gate = make_engine(tmp_path, key, FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS), sealer=s)
    run = tmp_path / "run"
    run.mkdir(exist_ok=True)
    (run / "policy.yaml").write_bytes(POLICY)
    (run / "sealed.json").write_bytes(sealed_doc(SEALED_EK, client_pub, "r1", b"run-pub"))
    eng.genesis()
    r = gate.on_request("api.example.com", "POST", "/v1/score", [], b'{"model":"small","count":1}')
    gate.on_response(r.seq, 200, [("content-type", "application/json")], b'{"score":0.5}')
    gate.on_request("evil.test", "POST", "/c/85010112345", [], DASH_SECRET)
    gate.wal.record_dns(T0, "85010112345.evil.test", "A", "block")
    (tmp_path / "out" / "r.txt").write_bytes(b"result")
    eng.tick()
    return run, s, client_sk
```

`tests/test_verify_sealed.py`:

```python
import pytest

from poi.ledger import pubkey_hex
from poi.policy import parse
from poi.seal.sealer import Sealer
from poi.verify import E_EVIDENCE, E_SEALED, VerifyError, verify_chain, verify_policy, verify_run

from helpers import POLICY, make_sealed_run


def test_without_key_chain_ok_and_schema_skipped(tmp_path, key):
    run, _, _ = make_sealed_run(tmp_path, key)
    res = verify_chain(run, pubkey_hex(key))
    verify_policy(res, run, parse(POLICY))
    assert res.sealed_unchecked == 3            # allowed egress, blocked egress, blocked dns


def test_with_key_everything_checked(tmp_path, key):
    run, s, _ = make_sealed_run(tmp_path, key)
    res = verify_chain(run, pubkey_hex(key))
    verify_policy(res, run, parse(POLICY), s)
    assert res.sealed_unchecked == 0
    v = verify_run(run, pubkey_hex(key), parse(POLICY), s)
    assert v.res.sealed_unchecked == 0
    assert verify_run(run, pubkey_hex(key), parse(POLICY)).res.sealed_unchecked == 3


def test_wrong_run_key_is_e_sealed(tmp_path, key):
    run, _, _ = make_sealed_run(tmp_path, key)
    res = verify_chain(run, pubkey_hex(key))
    with pytest.raises(VerifyError) as e:
        verify_policy(res, run, parse(POLICY), Sealer(b"x" * 32))
    assert e.value.code == E_SEALED


def test_missing_sealed_evidence_detected_without_key(tmp_path, key):
    run, _, _ = make_sealed_run(tmp_path, key)
    for p in (run / "evidence").glob("*.bin"):
        if p.read_bytes().startswith(b"POIEV1"):
            p.unlink()
    res = verify_chain(run, pubkey_hex(key))
    with pytest.raises(VerifyError) as e:
        verify_policy(res, run, parse(POLICY))
    assert e.value.code == E_EVIDENCE
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_verify_sealed.py -q` — Expected: FAIL (`ImportError: E_SEALED`).

- [ ] **Step 3: Implement** — w `src/poi/verify.py`:

Nagłówek modułu: `"""Independent verifier. Must import only: lthash, canonical, evidence, policy, seal (+ cryptography).`. Importy: `from poi.seal import FIELD_PREFIX, SealError`. Stałe: `E_SEALED = 18` po `E_LIVE`. W `VerifyResult` pole `sealed_unchecked: int = 0`.

Zastąpić `_check_egress`:

```python
def _opened(get: GetEvidence, sealer, seq: int) -> GetEvidence:
    def g(digest: str) -> bytes | None:
        data = get(digest)
        if data is None:
            return None
        try:
            return sealer.open_evidence(data)
        except SealError as e:
            raise VerifyError(E_SEALED, seq, f"evidence {digest[:12]}…: {e}")
    return g


def _check_egress(ev: Event, get: GetEvidence, policy: Policy, sealer=None) -> bool:
    """Check one egress/dns event. Returns False when it is sealed and no client key was given:
    then only evidence integrity (16) is checked, not schema conformance (14)."""
    f = ev.fields
    if sealer is not None:
        try:
            f = sealer.open_fields(f)
        except SealError as e:
            raise VerifyError(E_SEALED, ev.checkpoint, f"{ev.domain} seq {ev.seq}: {e}")
        get = _opened(get, sealer, ev.checkpoint)
    elif any(x.startswith(FIELD_PREFIX) for x in f):
        if ev.domain == "egress":
            _evidence(get, f[6], ev.checkpoint, f"egress {ev.seq} headers")
            _evidence(get, f[7], ev.checkpoint, f"egress {ev.seq} body")
        return False
    if ev.domain == "dns":
        _, _, _, name, qtype, verdict = f
        if verdict == "allow" and (name not in policy.hosts or qtype != "A"):
            raise VerifyError(E_SCHEMA, ev.checkpoint, f"dns seq {ev.seq}: {name} answered but not allowed")
        return True
    _, _, _, method, host, path, hdig, bdig, verdict, _ = f
    headers = _evidence(get, hdig, ev.checkpoint, f"egress {ev.seq} headers")
    body = _evidence(get, bdig, ev.checkpoint, f"egress {ev.seq} body")
    if verdict != "allow":
        return True
    d = policy.decide(host, method, path, body)
    if d.verdict != "allow" or d.body != body:
        raise VerifyError(E_SCHEMA, ev.checkpoint, f"egress seq {ev.seq} does not satisfy policy ({d.reason})")
    fwd = [["content-type", "application/json"]] if body else []
    fwd += [[k, v] for k, v in sorted(policy.forward_headers.items())]
    if json.loads(headers) != sorted(fwd):
        raise VerifyError(E_SCHEMA, ev.checkpoint, f"egress seq {ev.seq} forwarded unexpected headers")
    return True
```

`ChainVerifier.__init__(self, pubkey_hex: str, policy: Policy | None = None, sealer=None)` z `self.sealer = sealer`. W `feed` blok polityki:

```python
        unchecked = 0
        if self.policy is not None:
            get = get_evidence or (lambda d: None)
            _check_binding(cp, self.policy)
            for cseq, digest in new_configs:
                _check_config(cseq, digest, get, self.policy)
            for ev in new_events:
                if ev.domain == "ingress":
                    _check_ingress(ev, get)
                elif not _check_egress(ev, get, self.policy, self.sealer):
                    unchecked += 1

        res.accs, res.state_elements = accs, state
        res.sealed_unchecked += unchecked
```

`verify_policy(res, run_dir, policy, sealer=None)`: pętlę egress zastąpić

```python
    res.sealed_unchecked = 0
    for ev in res.egress:
        if not _check_egress(ev, get, policy, sealer):
            res.sealed_unchecked += 1
```

`verify_run(run_dir, pubkey_hex, policy, sealer=None)` tworzy `ChainVerifier(pubkey_hex, policy, sealer)`.

W `tests/test_verify_independence.py`: `ALLOWED = {"poi", "poi.canonical", "poi.lthash", "poi.evidence", "poi.policy", "poi.seal"}`.

- [ ] **Step 4: Run** `.venv/bin/pytest -m "not docker" -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/verify.py tests/helpers.py tests/test_verify_independence.py tests/test_verify_sealed.py
git commit -m "feat(seal): verifier opens sealed events with the client key, skips schema without it

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 9: Raport z kluczem klienta i bez niego

**Files:**
- Modify: `src/poi/report.py` (`build_report`, `render_text`)
- Test: `tests/test_report_sealed.py`

**Interfaces:**
- Consumes: `Sealer.open_fields/open_evidence`, `sealer.display_fields`, `sealer.is_sealed`, `sealer.LOCKED`, `helpers.make_sealed_run`.
- Produces: `build_report(res, run_dir, policy, fingerprints=None, sealer=None)`; nowy klucz raportu `"sealed_locked": int` (zdarzenia pokazane jako `🔒`, bo brak klucza).

- [ ] **Step 1: Write the failing test** — `tests/test_report_sealed.py`

```python
import math

from poi.fingerprint import FingerprintSet
from poi.ledger import pubkey_hex
from poi.policy import parse
from poi.report import build_report, render_text
from poi.verify import verify_chain

from helpers import DASH_SECRET, POLICY, make_sealed_run


def test_report_locked_then_opened(tmp_path, key):
    run, s, _ = make_sealed_run(tmp_path, key)
    res = verify_chain(run, pubkey_hex(key))
    policy = parse(POLICY)
    locked = build_report(res, run, policy)
    assert locked["sealed_locked"] == 3 and locked["allowed_requests"] == 1
    assert math.isinf(locked["capacity_bits_upper_bound"])
    assert all("85010112345" not in b["target"] and "evil" not in b["target"] for b in locked["blocked"])
    assert "🔒" in render_text(locked)
    fps = FingerprintSet(b"k" * 32)
    fps.add(DASH_SECRET, "patients.csv")
    opened = build_report(res, run, policy, fps, sealer=s)
    assert opened["sealed_locked"] == 0 and not math.isinf(opened["capacity_bits_upper_bound"])
    targets = {b["target"] for b in opened["blocked"]}
    assert {"POST evil.test/c/85010112345", "85010112345.evil.test"} <= targets
    assert opened["fingerprint_hits"] and opened["fingerprint_hits_in_allowed_traffic"] == 0
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_report_sealed.py -q` — Expected: FAIL (`unexpected keyword argument 'sealer'`).

- [ ] **Step 3: Implement** — w `src/poi/report.py` dodać importy `from poi.seal.sealer import LOCKED, display_fields, is_sealed` i zastąpić `build_report` do miejsca `leaked_allowed`:

```python
def build_report(res: VerifyResult, run_dir: Path, policy: Policy,
                 fingerprints: FingerprintSet | None = None, sealer=None) -> dict:
    """Without `sealer`, fields of a sealed run show as 🔒 and are not fingerprint-scanned."""
    run_dir = Path(run_dir)
    allowed: Counter = Counter()
    blocked: list[dict] = []
    dns: Counter = Counter()
    hits: list[dict] = []
    locked = 0
    for ev in res.egress:
        is_locked = sealer is None and any(is_sealed(x) for x in ev.fields)
        locked += is_locked
        f = sealer.open_fields(ev.fields) if sealer is not None else display_fields(ev.fields)
        scan = fingerprints is not None and not is_locked
        if ev.domain == "dns":
            dns[f[5]] += 1
            if f[5] == "block":
                blocked.append({"seq": ev.seq, "t": f[2], "kind": "dns", "target": f[3], "reason": "dns"})
            if scan and (found := fingerprints.scan(f[3].encode())):
                hits.append({"seq": ev.seq, "verdict": f[5], "sources": sorted(found)})
            continue
        _, _, t, method, host, path, _, bdig, verdict, reason = f
        if verdict == "allow":
            allowed[(host, method, path)] += 1
        else:
            blocked.append({"seq": ev.seq, "t": t, "kind": "http", "target": f"{method} {host}{path}",
                            "reason": reason})
        if scan:
            body = evidence.get(run_dir / "evidence", bdig) or b""
            if sealer is not None:
                body = sealer.open_evidence(body)
            if found := fingerprints.scan(body + b" " + path.encode()):
                hits.append({"seq": ev.seq, "verdict": verdict, "sources": sorted(found)})
    capacity = 0.0
    per_endpoint = []
    for (host, method, path), n in sorted(allowed.items()):
        ep = policy.find(host, method, path)
        bits = endpoint_capacity(ep) if ep else math.inf        # 🔒: endpoint unknown without the key
        capacity += bits * n
        per_endpoint.append({"endpoint": f"{method} {host}{path}", "requests": n, "bits_per_request": bits})
```

W zwracanym słowniku dodać `"sealed_locked": locked,`. W `render_text` po linii `DNS queries` dodać:

```python
    if r.get("sealed_locked"):
        lines.append(f"Sealed events shown as {LOCKED}: {r['sealed_locked']} (use --client-key to read them)")
```

- [ ] **Step 4: Run** `.venv/bin/pytest -m "not docker" -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/report.py tests/test_report_sealed.py
git commit -m "feat(seal): report reads sealed runs with the client key

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Runtime — kontener sealed, sekrety proxy, sprzątanie jako root

**Files:**
- Modify: `src/poi/runtime.py` (`Runtime.prepare`, `_wait_for_ca`, `create_workload`; nowa funkcja `root_rm`)
- Test: `tests/test_run_options.py` (nowe testy)

**Interfaces:**
- Consumes: `SECRETS_IN_PROXY` (Task 6).
- Produces:
  - `Runtime.prepare(policy_path, fingerprints=None, upstream_insecure=False, proxy_image=PROXY_IMAGE, run_id=None, secrets_dir=None, no_logs=False)`; `fingerprints = (path, key | None)`, przy `None` plik `fingerprint.key` nie powstaje.
  - `Runtime.create_workload(image, command, output_target, extra_ro_mounts=None, gpus=None, shm_size=None, env=None, *, output_dir=None, read_only=False, tmpfs=None, no_logs=False)`.
  - `root_rm(client, path, image=PROXY_IMAGE) -> None` — usuwa zawartość katalogu hosta jednorazowym kontenerem z uid 0 (pliki workloadu należą do roota).

- [ ] **Step 1: Write the failing test** — dopisać do `tests/test_run_options.py`:

```python
def test_create_workload_sealed_options(tmp_path):
    client = _Client()
    rt = Runtime(client, tmp_path, RuntimeInfo("r1", "int", "ext", "10.231.0.2"))
    out = tmp_path / "shm-out"
    rt.create_workload("img", None, "/srv/out", {}, output_dir=out, read_only=True,
                       tmpfs=["/tmp", "/cache"], no_logs=True)
    kw = client.containers.kwargs
    assert kw["read_only"] is True and kw["tmpfs"] == {"/tmp": "", "/cache": ""}
    assert kw["log_config"]["Type"] == "none"
    assert kw["volumes"][str(out)] == {"bind": "/srv/out", "mode": "rw"}
    assert str(tmp_path / "out") not in kw["volumes"]


def test_create_workload_default_is_not_sealed(tmp_path):
    client = _Client()
    Runtime(client, tmp_path, RuntimeInfo("r1", "int", "ext", "10.231.0.2")).create_workload("img", None, "/srv/out")
    kw = client.containers.kwargs
    assert not {"read_only", "tmpfs", "log_config"} & kw.keys()
    assert kw["volumes"][str(tmp_path / "out")] == {"bind": "/srv/out", "mode": "rw"}


def test_root_rm_runs_a_root_container(tmp_path):
    from poi.runtime import PROXY_IMAGE, root_rm
    seen = {}

    class C:
        class containers:
            @staticmethod
            def run(image, **kw):
                seen.update(kw, image=image)
    root_rm(C(), tmp_path)
    assert seen["image"] == PROXY_IMAGE and seen["user"] == "0:0" and seen["remove"] is True
    assert seen["network_mode"] == "none"
    assert seen["volumes"] == {str(tmp_path): {"bind": "/w", "mode": "rw"}}
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_run_options.py -q` — Expected: FAIL.

- [ ] **Step 3: Implement** — w `src/poi/runtime.py`:

```python
def root_rm(client: docker.DockerClient, path: Path, image: str = PROXY_IMAGE) -> None:
    """Remove the contents of a host directory as uid 0 (files the workload wrote belong to root)."""
    client.containers.run(image, entrypoint=["sh", "-c", "rm -rf /w/* /w/.[!.]* 2>/dev/null; true"],
                          user="0:0", network_mode="none", remove=True,
                          volumes={str(path): {"bind": "/w", "mode": "rw"}})
```

`prepare`:

```python
    def prepare(self, policy_path: Path, fingerprints: tuple[Path, bytes | None] | None = None,
                upstream_insecure: bool = False, proxy_image: str = PROXY_IMAGE, run_id: str | None = None,
                secrets_dir: Path | None = None, no_logs: bool = False) -> RuntimeInfo:
        """Create networks and start the proxy. Copies policy (and fingerprints) into the run dir.

        Sealed mode passes `secrets_dir` (tmpfs, mounted read-only into the proxy), no fingerprint key
        and `no_logs` (mitmdump prints request lines)."""
        self.run_dir.mkdir(parents=True, exist_ok=True)
        for d in ("ca", "proxy-wal", "evidence", "out"):
            (self.run_dir / d).mkdir(exist_ok=True)
        shutil.copyfile(policy_path, self.run_dir / "policy.yaml")
        if fingerprints is not None:
            shutil.copyfile(fingerprints[0], self.run_dir / "fingerprints.bin")
            if fingerprints[1] is not None:
                kp = self.run_dir / "fingerprint.key"
                kp.write_bytes(fingerprints[1])
                os.chmod(kp, 0o600)
        run_id = run_id or uuid.uuid4().hex[:8]
        net, subnet = self._create_internal_network(f"poi-{run_id}-int")
        ext = self.client.networks.create(f"poi-{run_id}-ext", driver="bridge")
        proxy_ip = str(subnet.network_address + 2)
        self.info = RuntimeInfo(run_id, net.name, ext.name, proxy_ip)
        cmd = ["--set", "ssl_insecure=true"] if upstream_insecure else []
        volumes = {str(self.run_dir): {"bind": "/run/poi", "mode": "rw"}}
        if secrets_dir is not None:
            volumes[str(secrets_dir)] = {"bind": SECRETS_IN_PROXY, "mode": "ro"}
        extra = {"log_config": docker.types.LogConfig(type="none")} if no_logs else {}
        proxy = self.client.containers.create(
            proxy_image, command=cmd, name=f"poi-{run_id}-proxy", network=ext.name,
            user=f"{os.getuid()}:{os.getgid()}",
            environment={"POI_PROXY_IP": proxy_ip},
            sysctls={"net.ipv4.ip_unprivileged_port_start": "0"},
            volumes=volumes, **extra)
        ...  # reszta (connect, start, _wait_for_ca, save) bez zmian
```

W `_wait_for_ca` zamienić rzucenie przy `exited` na:

```python
            if proxy.status == "exited":
                try:
                    logs = proxy.logs().decode(errors="replace")
                except APIError:
                    logs = "(proxy logs disabled)"
                raise RuntimeError("proxy exited:\n" + logs)
```

`create_workload`:

```python
    def create_workload(self, image: str, command: list[str] | None, output_target: str | None,
                        extra_ro_mounts: dict[str, str] | None = None, gpus: str | None = None,
                        shm_size: str | None = None, env: dict[str, str] | None = None, *,
                        output_dir: Path | None = None, read_only: bool = False,
                        tmpfs: list[str] | None = None, no_logs: bool = False):
        """Create (not start) the workload: internal network only, proxy env, CA, DNS → stub.

        Sealed mode: `output_dir` on tmpfs, read-only root filesystem, `tmpfs` scratch paths, no logs."""
        i = self.info
        proxy_url = f"http://{i.proxy_ip}:{PROXY_PORT}"
        volumes = {str(self.run_dir / "ca" / "mitmproxy-ca-cert.pem"): {"bind": CA_IN_WORKLOAD, "mode": "ro"}}
        if output_target:
            volumes[str(output_dir or self.run_dir / "out")] = {"bind": output_target, "mode": "rw"}
        ...  # extra_ro_mounts, env, gpus, shm_size bez zmian
        if read_only:
            extra["read_only"] = True
        if tmpfs:
            extra["tmpfs"] = {p: "" for p in tmpfs}
        if no_logs:
            extra["log_config"] = docker.types.LogConfig(type="none")
        w = self.client.containers.create(...)   # bez zmian
```

- [ ] **Step 4: Run** `.venv/bin/pytest -m "not docker" -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/runtime.py tests/test_run_options.py
git commit -m "feat(seal): sealed container options, proxy secrets mount, root cleanup helper

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 11: `SealedSession` i przebieg sealed w daemonie

**Files:**
- Create: `src/poi/sealed_run.py`
- Modify: `src/poi/daemon.py` (`RunSpec.sealed`, `_engine`, `start`, nowe `_start_sealed`, `resume`)
- Test: `tests/test_sealed_run.py`

**Interfaces:**
- Consumes: `bundle`, `grant`, `sealer`, `Runtime.prepare/create_workload` (Task 10), `root_rm`, `StateTracker(sealer=, sealed_info=)`.
- Produces:
  - `SealedOptions(client_pub: bytes, mounts: dict[str, str], tmpfs: list[str] = ["/tmp"], allow_swap=False, grant_timeout=600.0)` (`mounts`: ścieżka paczki → cel w kontenerze).
  - `SealedSession(run_dir, opts, run_id=None, shm_root=SHM, swap=None)` z `.run_id`, `.tmp`, `.secrets`, `.out`, `.ro_mounts: dict[str, str]`, `.sealer`, metodami `check_swap()`, `setup(want_fingerprint_key: bool)`, `config_info(out_target) -> dict`, `finish() -> Path | None`, `wipe(root_rm=None)`.
  - `swap_active(proc_swaps=Path("/proc/swaps")) -> bool`, `wipe_dir(path, root_rm=None)`, `run_id_of(run_dir) -> str | None`, `SHM = Path("/dev/shm")`.
  - `daemon.RunSpec.sealed: SealedOptions | None = None`; `daemon.resume` rzuca `SealError` dla uruchomienia sealed.

- [ ] **Step 1: Write the failing test** — `tests/test_sealed_run.py`

```python
import os
import threading
import time
from pathlib import Path

import pytest

from poi import canonical as c
from poi import daemon
from poi.seal import SealError, bundle, kem
from poi.seal.grant import FP_LABEL, bundle_label, make_grant
from poi.seal.sealer import open_sealed_doc
from poi.sealed_run import SealedOptions, SealedSession, run_id_of, swap_active, wipe_dir

HEADER = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"


def test_swap_active(tmp_path):
    p = tmp_path / "swaps"
    p.write_text(HEADER)
    assert not swap_active(p)
    p.write_text(HEADER + "/swapfile file 1024 0 -2\n")
    assert swap_active(p)


def test_swap_refused_before_anything_is_written(tmp_path):
    s = SealedSession(tmp_path / "run", SealedOptions(b"", {}), shm_root=tmp_path / "shm", swap=True)
    with pytest.raises(SealError, match="swap"):
        s.setup(False)
    assert not (tmp_path / "shm").exists() and not (tmp_path / "run" / "run.pub").exists()


def _send_grant(run: Path, keys_for):
    p = run / "run.pub"
    while not p.exists():
        time.sleep(0.05)
    g = make_grant(p.read_bytes(), keys_for())
    (run / "grant.tmp").write_bytes(g)
    os.replace(run / "grant.tmp", run / "grant.bin")


def test_session_lifecycle(tmp_path):
    csk, cpk = kem.generate()
    data = tmp_path / "data"
    data.mkdir()
    (data / "secret.txt").write_bytes(b"85010112345")
    b = tmp_path / "d.sealed"
    digest = bundle.seal_dir(data, b, cpk)
    run = tmp_path / "run"
    s = SealedSession(run, SealedOptions(cpk, {str(b): "/data"}, grant_timeout=30), run_id="r1",
                      shm_root=tmp_path / "shm", swap=False)
    th = threading.Thread(target=_send_grant, args=(run, lambda: {
        bundle_label(digest): bundle.dek_for(b, csk), FP_LABEL: b"f" * 32}))
    th.start()
    s.setup(want_fingerprint_key=True)
    th.join()

    assert run_id_of(run) == "r1"
    (src, target), = s.ro_mounts.items()
    assert target == "/data" and Path(src).is_relative_to(tmp_path / "shm" / "poi-r1")
    assert (Path(src) / "secret.txt").read_bytes() == b"85010112345"
    assert (tmp_path / "shm" / "poi-r1").stat().st_mode & 0o777 == 0o700
    assert (s.secrets / "fingerprint.key").read_bytes() == b"f" * 32 and len((s.secrets / "ek").read_bytes()) == 32
    owner = open_sealed_doc((run / "sealed.json").read_bytes(), csk)
    assert owner.open_evidence(s.sealer.seal_evidence(b"x")) == b"x"
    info = s.config_info("/srv/out")
    assert info == {"client_pub": c.b2b256(cpk), "run_pub": c.b2b256((run / "run.pub").read_bytes()),
                    "mounts": {"/data": digest}, "swap": False, "out_target": "/srv/out"}

    (s.out / "result.json").write_bytes(b"42")
    sealed_out = s.finish()
    assert sealed_out == run / "out.sealed"
    bundle.unseal_to(sealed_out, bundle.dek_for(sealed_out, csk), tmp_path / "o")
    assert (tmp_path / "o" / "result.json").read_bytes() == b"42"
    s.wipe()
    assert not (tmp_path / "shm" / "poi-r1").exists() and s.sealer is None
    assert not any(b"85010112345" in p.read_bytes() for p in run.rglob("*") if p.is_file())


def test_finish_without_output_writes_nothing(tmp_path):
    s = SealedSession(tmp_path / "run", SealedOptions(b"", {}), run_id="r2", shm_root=tmp_path, swap=False)
    s.out.mkdir(parents=True)
    assert s.finish() is None


def test_wipe_dir_falls_back_to_root_rm(tmp_path):
    d = tmp_path / "w"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "f").write_bytes(b"secret")
    os.chmod(d / "sub", 0o500)                     # like a root-owned dir: contents cannot be removed
    calls = []

    def fake_root_rm(p):
        calls.append(p)
        os.chmod(p / "sub", 0o700)
        for x in (p / "sub").iterdir():
            x.unlink()
    wipe_dir(d, fake_root_rm)
    assert not d.exists()
    assert calls == [d] or os.geteuid() == 0      # root can remove it without the fallback


def test_resume_refuses_sealed_run(tmp_path):
    (tmp_path / "sealed.json").write_text("{}")
    with pytest.raises(SealError, match="cannot be resumed"):
        daemon.resume(tmp_path, tmp_path / "k", client=object())
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_sealed_run.py -q` — Expected: FAIL (brak `poi.sealed_run`).

- [ ] **Step 3: Implement** — `src/poi/sealed_run.py`

```python
"""Sealed run lifecycle (spec §6): run key → client grant → tmpfs workspace → EK → sealed output → wipe."""
from __future__ import annotations

import json
import logging
import os
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from poi import canonical as c
from poi.seal import SealError, bundle
from poi.seal import sealer as sl
from poi.seal.grant import FP_LABEL, RunKey, bundle_label, wait_for_grant

log = logging.getLogger("poi")
SHM = Path("/dev/shm")
_ZERO = bytes(1 << 20)


def swap_active(proc_swaps: Path = Path("/proc/swaps")) -> bool:
    try:
        return len(proc_swaps.read_text().strip().splitlines()) > 1
    except FileNotFoundError:
        return False


@dataclass
class SealedOptions:
    client_pub: bytes
    mounts: dict[str, str]                       # sealed bundle path -> container target
    tmpfs: list[str] = field(default_factory=lambda: ["/tmp"])
    allow_swap: bool = False
    grant_timeout: float = 600.0


def _write_secret(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def wipe_dir(path: Path, root_rm: Callable[[Path], None] | None = None) -> None:
    """Overwrite regular files with zeros (best effort), then remove the tree; root_rm handles root-owned leftovers."""
    path = Path(path)
    if not path.exists():
        return
    for root, _, files in os.walk(path):
        for name in files:
            p = Path(root) / name
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                left = p.stat().st_size
                with open(p, "r+b") as f:
                    while left > 0:
                        left -= f.write(_ZERO[:min(left, len(_ZERO))])
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)
    if path.exists() and root_rm is not None:
        root_rm(path)
        shutil.rmtree(path, ignore_errors=True)


def run_id_of(run_dir: Path) -> str | None:
    """Run id from run.pub (written first) or runtime.json."""
    for name in ("run.pub", "runtime.json"):
        try:
            return json.loads((Path(run_dir) / name).read_text())["run_id"]
        except (FileNotFoundError, ValueError, KeyError):
            continue
    return None


class SealedSession:
    def __init__(self, run_dir: Path, opts: SealedOptions, run_id: str | None = None,
                 shm_root: Path = SHM, swap: bool | None = None) -> None:
        self.run_dir = Path(run_dir).resolve()
        self.opts = opts
        self.run_id = run_id or uuid.uuid4().hex[:8]
        self.tmp = Path(shm_root) / f"poi-{self.run_id}"
        self.secrets, self.out = self.tmp / "secrets", self.tmp / "out"
        self.swap = swap_active() if swap is None else swap
        self.ro_mounts: dict[str, str] = {}
        self.bundle_digests: dict[str, str] = {}
        self.run_pub_raw = b""
        self.sealer: sl.Sealer | None = None

    def check_swap(self) -> None:
        if self.swap and not self.opts.allow_swap:
            raise SealError("swap is active, so decrypted data could reach disk (--allow-swap to accept)")

    def setup(self, want_fingerprint_key: bool) -> None:
        """Publish run.pub, wait for the client's grant, decrypt bundles into tmpfs, create EK."""
        self.check_swap()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.tmp.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.tmp, 0o700)
        for d in (self.secrets, self.tmp / "data"):
            d.mkdir(mode=0o700, exist_ok=True)
        self.out.mkdir(exist_ok=True)
        os.chmod(self.out, 0o777)            # any workload uid may write; the 0700 parent keeps others out
        rk = RunKey.generate(self.run_id)
        self.run_pub_raw = rk.pub_bytes()
        (self.run_dir / "run.pub").write_bytes(self.run_pub_raw)
        labels = {}
        for path, target in self.opts.mounts.items():
            self.bundle_digests[target] = bundle.file_digest(Path(path))
            labels[path] = bundle_label(self.bundle_digests[target])
        needed = set(labels.values()) | ({FP_LABEL} if want_fingerprint_key else set())
        log.info("sealed run %s: send %s to the data owner and put their grant at %s",
                 self.run_id, self.run_dir / "run.pub", self.run_dir / "grant.bin")
        keys = wait_for_grant(self.run_dir / "grant.bin", rk, needed, self.opts.grant_timeout)
        del rk                               # the run private key is gone: the grant is useless from now on
        for n, (path, target) in enumerate(self.opts.mounts.items()):
            dest = self.tmp / "data" / str(n)
            bundle.unseal_to(Path(path), keys[labels[path]], dest)
            self.ro_mounts[str(dest)] = target
        if want_fingerprint_key:
            _write_secret(self.secrets / "fingerprint.key", keys[FP_LABEL])
        ek = sl.new_ek()
        _write_secret(self.secrets / "ek", ek)
        (self.run_dir / "sealed.json").write_bytes(
            sl.sealed_doc(ek, self.opts.client_pub, self.run_id, self.run_pub_raw))
        self.sealer = sl.Sealer(ek)

    def config_info(self, out_target: str | None) -> dict:
        return {"client_pub": c.b2b256(self.opts.client_pub), "run_pub": c.b2b256(self.run_pub_raw),
                "mounts": dict(sorted(self.bundle_digests.items())), "swap": self.swap, "out_target": out_target}

    def finish(self) -> Path | None:
        """Seal the output directory to the client as run/out.sealed (nothing if it is empty)."""
        if not self.out.exists() or not any(self.out.iterdir()):
            return None
        out = self.run_dir / "out.sealed"
        bundle.seal_dir(self.out, out, self.opts.client_pub, kind="out")
        return out

    def wipe(self, root_rm: Callable[[Path], None] | None = None) -> None:
        wipe_dir(self.tmp, root_rm)
        self.sealer = None
```

W `src/poi/daemon.py`: importy `from poi.runtime import Runtime, RuntimeInfo, ensure_proxy_image, root_rm`, `from poi.seal import SealError`, `from poi.sealed_run import SealedOptions, SealedSession`. W `RunSpec` pole `sealed: SealedOptions | None = None`. `_engine`:

```python
def _engine(client, rt: Runtime, policy: pol.Policy, key_path: Path, output_dir: Path | None = None,
            sealer=None, sealed_info: dict | None = None) -> Engine:
    w = rt.workload()
    out_dir = output_dir or rt.run_dir / "out"
    output = (out_dir, policy.output_volume) if policy.output_volume else None
    tracker = StateTracker(DockerContainerFS(client, w), output, image_mode=policy.image_attestation,
                           attest_mounts=tuple(policy.attest_mounts), sealer=sealer, sealed_info=sealed_info)
    ...  # on_violation i return bez zmian
```

`start` i nowe `_start_sealed`:

```python
def start(spec: RunSpec, client=None) -> Runtime:
    client = client or docker.from_env()
    policy = pol.load(spec.policy_path)
    ensure_proxy_image(client)
    if spec.sealed is not None:
        return _start_sealed(spec, client, policy)
    ...  # dotychczasowy przebieg bez zmian


def _start_sealed(spec: RunSpec, client, policy: pol.Policy) -> Runtime:
    """Spec §6: everything decrypted lives in tmpfs; the workload is always removed and tmpfs wiped."""
    s = SealedSession(spec.run_dir, spec.sealed)
    rt = Runtime(client, spec.run_dir)
    try:
        s.setup(want_fingerprint_key=spec.fingerprints is not None)
        rt.prepare(spec.policy_path, spec.fingerprints, policy.upstream_insecure,
                   run_id=s.run_id, secrets_dir=s.secrets, no_logs=True)
        rt.create_workload(spec.image, spec.command, policy.output_volume,
                           {**(spec.extra_ro_mounts or {}), **s.ro_mounts}, spec.gpus, spec.shm_size, spec.env,
                           output_dir=s.out, read_only=True, tmpfs=spec.sealed.tmpfs, no_logs=True)
        engine = _engine(client, rt, policy, spec.key_path, output_dir=s.out, sealer=s.sealer,
                         sealed_info=s.config_info(policy.output_volume))
        engine.genesis()
        rt.workload().start()
        loop(engine, rt, policy.tick_seconds, spec.max_ticks)
        s.finish()
    finally:
        if rt.info is not None:
            rt.teardown(keep_workload=False)
        s.wipe(root_rm=lambda p: root_rm(client, p))
    return rt
```

Na początku `resume` (przed `docker.from_env()`):

```python
    if (Path(run_dir) / "sealed.json").exists():
        raise SealError("sealed runs cannot be resumed: their keys existed only in the stopped process")
```

- [ ] **Step 4: Run** `.venv/bin/pytest -m "not docker" -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/sealed_run.py src/poi/daemon.py tests/test_sealed_run.py
git commit -m "feat(seal): sealed run lifecycle (grant, tmpfs, run key, sealed output, wipe)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 12: CLI

**Files:**
- Modify: `src/poi/cli.py`
- Test: `tests/test_cli_sealed.py`

**Interfaces:**
- Consumes: wszystko z Tasks 2–11.
- Produces: komendy `client-keygen KEY`, `seal --data DIR --to PUB --out FILE`, `grant BUNDLE... --run-pub FILE --key KEY [--fp-key FILE] --out FILE`, `unseal BUNDLE --key KEY --out DIR`; `run` z `--sealed --client-pub --sealed-mount B:T (wielokrotnie) --tmpfs PATH (wielokrotnie) --allow-swap --grant-timeout S`; `verify`/`report`/`dashboard` z `--client-key`. Kody wyjścia: złe hasło lub inny błąd sealed w komendach klienta → 2; nieudane odszyfrowanie uruchomienia w `verify`/`report` → 18.

- [ ] **Step 1: Write the failing test** — `tests/test_cli_sealed.py`

```python
import json
from pathlib import Path

import pytest

from poi import cli, daemon
from poi.cli import main
from poi.seal import bundle, keyfile
from poi.seal.grant import FP_LABEL, RunKey, bundle_label, open_grant
from poi.verify import E_SEALED

from helpers import FAST_KDF, make_sealed_run


@pytest.fixture
def pw(monkeypatch):
    monkeypatch.setenv(keyfile.PASSWORD_ENV, "pw")
    return monkeypatch


def test_keygen_seal_unseal_grant(tmp_path, pw, capsys):
    ck = tmp_path / "client.key"
    assert main(["client-keygen", str(ck)]) == 0
    data = tmp_path / "data"
    data.mkdir()
    (data / "secret.txt").write_bytes(b"85010112345")
    sealed = tmp_path / "d.sealed"
    assert main(["seal", "--data", str(data), "--to", str(tmp_path / "client.pub"), "--out", str(sealed)]) == 0
    assert main(["unseal", str(sealed), "--key", str(ck), "--out", str(tmp_path / "back")]) == 0
    assert (tmp_path / "back" / "secret.txt").read_bytes() == b"85010112345"
    rk = RunKey.generate("r1")
    (tmp_path / "run.pub").write_bytes(rk.pub_bytes())
    (tmp_path / "fp.key").write_bytes(b"f" * 32)
    assert main(["grant", str(sealed), "--run-pub", str(tmp_path / "run.pub"), "--key", str(ck),
                 "--fp-key", str(tmp_path / "fp.key"), "--out", str(tmp_path / "grant.bin")]) == 0
    keys = open_grant((tmp_path / "grant.bin").read_bytes(), rk)
    sk = keyfile.load_private(ck, "pw")
    assert keys == {FP_LABEL: b"f" * 32, bundle_label(bundle.file_digest(sealed)): bundle.dek_for(sealed, sk)}
    pw.setenv(keyfile.PASSWORD_ENV, "bad")
    assert main(["unseal", str(sealed), "--key", str(ck), "--out", str(tmp_path / "x")]) == 2
    assert "wrong password" in capsys.readouterr().err


def test_verify_and_report_with_and_without_client_key(tmp_path, key, pw, capsys):
    ck = tmp_path / "client.key"
    run, _, _ = make_sealed_run(tmp_path, key, client_pub=keyfile.create(ck, "pw", **FAST_KDF))
    assert main(["verify", str(run)]) == 0
    assert "sealed: 3 egress events not schema-checked" in capsys.readouterr().out
    assert main(["verify", str(run), "--client-key", str(ck)]) == 0
    assert "sealed:" not in capsys.readouterr().out
    assert main(["report", str(run), "--json", "--client-key", str(ck)]) == 0
    r = json.loads(capsys.readouterr().out)
    assert any(b["target"] == "POST evil.test/c/85010112345" for b in r["blocked"])
    assert main(["verify", str(run), "--live"]) == 2
    keyfile.create(tmp_path / "other.key", "pw", **FAST_KDF)
    assert main(["verify", str(run), "--client-key", str(tmp_path / "other.key")]) == E_SEALED
    pw.setenv(keyfile.PASSWORD_ENV, "bad")
    assert main(["verify", str(run), "--client-key", str(ck)]) == 2


def test_run_argument_rules(tmp_path):
    base = ["run", "--policy", "p", "--key", "k", "--run-dir", str(tmp_path)]
    with pytest.raises(SystemExit):
        main(base + ["--sealed-mount", "a.sealed:/data", "img"])
    with pytest.raises(SystemExit):
        main(base + ["--sealed", "img"])
    with pytest.raises(SystemExit):
        main(base + ["--sealed", "--client-pub", "c.pub", "--fingerprints", "f", "--fp-key", "k", "img"])


def test_run_builds_sealed_spec(tmp_path, monkeypatch):
    pk = keyfile.create(tmp_path / "client.key", "pw", **FAST_KDF)
    seen = {}

    class RT:
        def teardown(self, keep_workload):
            seen["keep"] = keep_workload

    monkeypatch.setattr(daemon, "start", lambda spec: seen.setdefault("spec", spec) and RT())
    assert cli.main(["run", "--policy", "p.yaml", "--key", "k", "--run-dir", str(tmp_path), "--sealed",
                     "--client-pub", str(tmp_path / "client.pub"), "--sealed-mount", "d.sealed:/data",
                     "--tmpfs", "/cache", "--allow-swap", "--grant-timeout", "5", "--fingerprints", "fp.bin",
                     "img", "python", "/app/job.py"]) == 0
    s = seen["spec"]
    assert s.sealed.client_pub == pk and s.sealed.mounts == {"d.sealed": "/data"}
    assert s.sealed.tmpfs == ["/tmp", "/cache"] and s.sealed.allow_swap and s.sealed.grant_timeout == 5
    assert s.fingerprints == (Path("fp.bin"), None) and seen["keep"] is False
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_cli_sealed.py -q` — Expected: FAIL (nieznane komendy).

- [ ] **Step 3: Implement** — w `src/poi/cli.py` (docstring modułu uzupełnić o `client-keygen | seal | grant | unseal`).

Nowe funkcje (przed `cmd_keygen`):

```python
def _client_sk(path) -> bytes:
    from poi.seal import keyfile
    return keyfile.load_private(Path(path), keyfile.get_password())


def _client_sealer(args, sealed_raw: bytes | None = None):
    """(Sealer | None, exit code) for --client-key; reads run_dir/sealed.json unless `sealed_raw` is given."""
    if not getattr(args, "client_key", None):
        return None, 0
    from poi.seal import SealError
    from poi.seal.keyfile import BadPassword
    from poi.seal.sealer import open_sealed_doc
    from poi.verify import E_SEALED
    try:
        raw = sealed_raw if sealed_raw is not None else (Path(args.run_dir) / "sealed.json").read_bytes()
    except FileNotFoundError:
        print("not a sealed run: sealed.json is missing", file=sys.stderr)
        return None, 2
    try:
        return open_sealed_doc(raw, _client_sk(args.client_key)), 0
    except BadPassword as e:
        print(f"sealed: {e}", file=sys.stderr)
        return None, 2
    except SealError as e:
        print(f"FAIL [{E_SEALED}] {e}", file=sys.stderr)
        return None, E_SEALED


def cmd_client_keygen(args) -> int:
    from poi.seal import keyfile
    keyfile.create(Path(args.key), keyfile.get_password(confirm=True))
    print(f"client key {args.key}, public key {keyfile.pub_path(Path(args.key))}")
    return 0


def cmd_seal(args) -> int:
    from poi.seal import bundle, keyfile
    digest = bundle.seal_dir(Path(args.data), Path(args.out), keyfile.load_public(Path(args.to)))
    print(f"{args.out} {digest}")
    return 0


def cmd_grant(args) -> int:
    from poi.seal import SealError, bundle
    from poi.seal.grant import FP_LABEL, bundle_label, make_grant
    try:
        sk = _client_sk(args.key)
        keys = {bundle_label(bundle.file_digest(Path(b))): bundle.dek_for(Path(b), sk) for b in args.bundles}
        if args.fp_key:
            keys[FP_LABEL] = Path(args.fp_key).read_bytes()
        raw = make_grant(Path(args.run_pub).read_bytes(), keys)
    except SealError as e:
        print(f"sealed: {e}", file=sys.stderr)
        return 2
    out = Path(args.out)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_bytes(raw)
    os.replace(tmp, out)                    # the run polls this file: never expose a partial grant
    print(f"grant with {len(keys)} key(s) → {out}")
    return 0


def cmd_unseal(args) -> int:
    from poi.seal import SealError, bundle
    try:
        bundle.unseal_to(Path(args.bundle), bundle.dek_for(Path(args.bundle), _client_sk(args.key)), Path(args.out))
    except SealError as e:
        print(f"sealed: {e}", file=sys.stderr)
        return 2
    print(f"{args.bundle} → {args.out}")
    return 0
```

`cmd_run`:

```python
def cmd_run(args) -> int:
    from poi import daemon
    from poi.seal import SealError
    if args.sealed_mount and not args.sealed:
        raise SystemExit("--sealed-mount requires --sealed")
    sealed = None
    if args.sealed:
        from poi.seal.keyfile import load_public
        from poi.sealed_run import SealedOptions
        if not args.client_pub:
            raise SystemExit("--sealed requires --client-pub")
        if args.fp_key:
            raise SystemExit("in sealed mode the fingerprint key comes from the client's grant: drop --fp-key")
        sealed = SealedOptions(load_public(Path(args.client_pub)),
                               dict(m.split(":", 1) for m in args.sealed_mount),
                               list(dict.fromkeys(["/tmp", *args.tmpfs])), args.allow_swap, args.grant_timeout)
        fps = (Path(args.fingerprints), None) if args.fingerprints else None
    else:
        fps = (Path(args.fingerprints), Path(args.fp_key).read_bytes()) if args.fingerprints else None
    mounts = dict(m.split(":", 1) for m in args.mount)
    env = dict(e.split("=", 1) for e in args.env)
    spec = daemon.RunSpec(Path(args.run_dir), Path(args.policy), Path(args.key), args.image,
                          args.cmd or None, fps, mounts, gpus=args.gpus, shm_size=args.shm_size, env=env,
                          sealed=sealed)
    try:
        rt = daemon.start(spec)
    except SealError as e:
        print(f"sealed: {e}", file=sys.stderr)
        return 2
    rt.teardown(keep_workload=not args.rm and sealed is None)
    return 0
```

`cmd_resume`: owinąć w `try/except SealError as e: print(f"sealed: {e}", file=sys.stderr); return 2` (import `from poi.seal import SealError`).

`_verified(args, sealer=None)`: `verify_policy(res, run, policy, sealer)`.

`cmd_verify`:

```python
def cmd_verify(args) -> int:
    from poi.verify import E_LIVE, VerifyError
    if args.live and (Path(args.run_dir) / "sealed.json").exists():
        print("--live is not available for sealed runs: the container was removed", file=sys.stderr)
        return 2
    sealer, rc = _client_sealer(args)
    if rc:
        return rc
    try:
        res, _ = _verified(args, sealer)
        ...  # blok --live bez zmian
    except VerifyError as e:
        print(f"FAIL {e}", file=sys.stderr)
        return e.code
    print(f"OK {len(res.checkpoints)} checkpoints, {len(res.egress)} egress events, "
          f"state {res.last['state']['digest']}")
    if res.sealed_unchecked:
        print(f"sealed: {res.sealed_unchecked} egress events not schema-checked (needs --client-key)")
    return 0
```

`cmd_report`: na początku `sealer, rc = _client_sealer(args)` / `if rc: return rc`; `_verified(args, sealer)`; `build_report(res, Path(args.run_dir), policy, fps, sealer)`.

`cmd_clean`:

```python
def cmd_clean(args) -> int:
    import docker
    from poi.runtime import Runtime, RuntimeInfo, root_rm
    from poi.sealed_run import SHM, run_id_of, wipe_dir
    run = Path(args.run_dir)
    client = docker.from_env()
    if (run / "runtime.json").exists():
        Runtime(client, run, RuntimeInfo.load(run)).teardown(keep_workload=False)
    if (rid := run_id_of(run)) is not None:
        wipe_dir(SHM / f"poi-{rid}", lambda p: root_rm(client, p))     # leftovers of a crashed sealed run
    return 0
```

`build_dashboard`: po `pubkey = ...` dodać

```python
    sealer = None
    if args.client_key:
        from poi.source import NotFound
        try:
            sealed_raw = source.sealed()
        except NotFound:
            raise SystemExit("not a sealed run: the operator feed has no sealed.json")
        sealer, rc = _client_sealer(args, sealed_raw)
        if rc:
            raise SystemExit(rc)
```

i przekazać `sealer=sealer` do `Mirror(...)` (parametr dodaje Task 13 — do tego czasu Task 12 nie dotyka `build_dashboard`; ten fragment wprowadź w Task 13, Step 3).

Parser (`build_parser`):

```python
    s = sub.add_parser("client-keygen", help="data owner: create a password-protected sealing key")
    s.add_argument("key")
    s.set_defaults(fn=cmd_client_keygen)

    s = sub.add_parser("seal", help="data owner: encrypt a data directory for a sealed run")
    s.add_argument("--data", required=True)
    s.add_argument("--to", required=True, help="client public key (client.pub)")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_seal)

    s = sub.add_parser("grant", help="data owner: release data keys to one sealed run")
    s.add_argument("bundles", nargs="+")
    s.add_argument("--run-pub", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--fp-key", help="fingerprint key to hand to the run's proxy")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_grant)

    s = sub.add_parser("unseal", help="data owner: decrypt a sealed bundle (e.g. out.sealed)")
    s.add_argument("bundle")
    s.add_argument("--key", required=True)
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_unseal)
```

W parserze `run` (przed `image`):

```python
    s.add_argument("--sealed", action="store_true", help="client data only in tmpfs; evidence sealed to the client")
    s.add_argument("--client-pub", help="client public key (sealed mode)")
    s.add_argument("--sealed-mount", action="append", default=[], help="BUNDLE:TARGET sealed read-only mount")
    s.add_argument("--tmpfs", action="append", default=[], help="extra writable tmpfs path (sealed; /tmp always)")
    s.add_argument("--allow-swap", action="store_true", help="sealed: run even though swap is active")
    s.add_argument("--grant-timeout", type=float, default=600.0, help="sealed: seconds to wait for grant.bin")
```

Dla `verify` i `report` w pętli: `s.add_argument("--client-key", help="sealed runs: read sealed fields and evidence")`; dla `dashboard`: `s.add_argument("--client-key")`.

- [ ] **Step 4: Run** `.venv/bin/pytest -m "not docker" -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/cli.py tests/test_cli_sealed.py
git commit -m "feat(seal): CLI for keys, bundles, grants and sealed runs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 13: `sealed.json` w feedzie, mirror i dashboard

**Files:**
- Modify: `src/poi/serve.py` (trasa `/v1/sealed`), `src/poi/source.py` (`Source.sealed`, `LocalSource.sealed`, `HttpSource.sealed`)
- Modify: `src/poi/mirror.py` (`Mirror.__init__`, `_copy_sealed_doc`, `fields`, `evidence`, `_after_feed`)
- Modify: `src/poi/dashboard.py` (`_evidence`, `_event_row`, `_cp_stats`, `summary`, `event`)
- Modify: `src/poi/cli.py` (`build_dashboard` — fragment z Task 12)
- Test: `tests/test_serve.py` (nowy test), `tests/test_dashboard_sealed.py`

**Interfaces:**
- Consumes: `Sealer`, `display_fields`, `is_sealed`, `EV_MAGIC`, `ChainVerifier(..., sealer)`, `helpers.make_sealed_run`, `cli._client_sealer`.
- Produces: `GET /v1/sealed`; `Source.sealed() -> bytes` (`NotFound`, gdy uruchomienie nie jest sealed); `Mirror(..., sealer=None)` z `Mirror.fields(list[str]) -> list[str]` (odszyfrowane albo `🔒`) i `Mirror.evidence(digest) -> bytes | None` (szyfrogram bez klucza → `None`); mirror kopiuje `sealed.json`, więc `poi verify MIRROR --client-key` działa.

- [ ] **Step 1: Write the failing test** — dopisać do `tests/test_serve.py`:

```python
def _get(base, path):
    req = urllib.request.Request(base + path, headers={"authorization": f"Bearer {TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_sealed_doc_route_and_sources(served):
    from poi.source import HttpSource, LocalSource, NotFound
    base, _, run = served
    assert _get(base, "/v1/sealed")[0] == 404
    with pytest.raises(NotFound):
        LocalSource(run).sealed()
    with pytest.raises(NotFound):
        HttpSource(base, TOKEN).sealed()
    (run / "sealed.json").write_bytes(b'{"v":1}')
    assert _get(base, "/v1/sealed") == (200, b'{"v":1}')
    assert LocalSource(run).sealed() == HttpSource(base, TOKEN).sealed() == b'{"v":1}'
```

`tests/test_dashboard_sealed.py`:

```python
import json

from poi.dashboard import DashboardApp
from poi.fingerprint import FingerprintSet
from poi.ledger import pubkey_hex
from poi.mirror import Mirror
from poi.source import LocalSource

from helpers import DASH_SECRET, make_sealed_run


def _app(tmp_path, key, run, sealer, name):
    fp = FingerprintSet(b"k" * 32)
    fp.add(DASH_SECRET, "patients.csv")
    m = Mirror(tmp_path / name, LocalSource(run, runtime=lambda: {"status": "exited"}), pubkey_hex(key), fp,
               sleep=lambda s: None, sealer=sealer)
    m.sync_once(wait=0)
    assert m.error is None
    return DashboardApp(m, "local")


def _blocked_http(app):
    return app.event(next(r["seq"] for r in app.events(None, 100, "blocked") if r["kind"] == "http"))


def test_without_client_key_everything_client_side_is_locked(tmp_path, key):
    run, _, _ = make_sealed_run(tmp_path, key)
    app = _app(tmp_path, key, run, None, "m1")
    assert (app.m.dir / "sealed.json").exists()
    row = _blocked_http(app)
    assert (row["host"], row["path"], row["body"], row["headers"]) == ("🔒", "🔒", None, None)
    assert app.m.hits == {}
    s = app.summary()
    assert s["blocked"] == 2 and s["capacity_bits"] is None
    assert app.checkpoint(1)["files"]["added"] == ["🔒"]
    dump = json.dumps([s, app.events(None, 100, "all"), app.checkpoint(1), row], ensure_ascii=False)
    assert "85010112345" not in dump and "evil.test" not in dump


def test_with_client_key_content_is_shown(tmp_path, key):
    run, sealer, _ = make_sealed_run(tmp_path, key)
    app = _app(tmp_path, key, run, sealer, "m2")
    row = _blocked_http(app)
    assert (row["host"], row["path"]) == ("evil.test", "/c/85010112345")
    assert "85010112345" in row["body"]["text"] and row["seq"] in app.m.hits
    assert app.summary()["capacity_bits"] is not None
    assert app.checkpoint(1)["files"]["added"] == ["/srv/out/r.txt"]
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_serve.py tests/test_dashboard_sealed.py -q` — Expected: FAIL.

- [ ] **Step 3: Implement**

`src/poi/serve.py`, w `do_GET` przed trasą `runtime`:

```python
            if kind == "sealed" and arg is None:
                return self._file(run_dir / "sealed.json", "application/json")
```

`src/poi/source.py`: w `Source` (Protocol) `def sealed(self) -> bytes: ...`; w `LocalSource`:

```python
    def sealed(self) -> bytes:
        return self._read(self.run_dir / "sealed.json")
```

w `HttpSource`:

```python
    def sealed(self) -> bytes:
        return self._get("/v1/sealed")
```

`src/poi/mirror.py`: import `from poi.seal.sealer import EV_MAGIC, display_fields, is_sealed`. `Mirror.__init__` dostaje ostatni parametr `sealer=None`; przypisanie `self.sealer = sealer` przed `self.policy = ...`, a koniec konstruktora:

```python
        self.policy = self._load_policy()
        self._copy_sealed_doc()
        self.verifier = ChainVerifier(pubkey_hex, self.policy, sealer)
        self.replay_local()
```

Nowe metody (sekcja setup):

```python
    def _copy_sealed_doc(self) -> None:
        """Keep sealed.json next to the mirrored run so `poi verify MIRROR --client-key` works."""
        p = self.dir / "sealed.json"
        if p.exists():
            return
        try:
            _write_atomic(p, self.source.sealed())
        except SourceError:
            pass                                    # not a sealed run

    def fields(self, f: list[str]) -> list[str]:
        """Element fields for display: decrypted with the client key, 🔒 without it."""
        return self.sealer.open_fields(f) if self.sealer is not None else display_fields(f)

    def evidence(self, digest: str) -> bytes | None:
        data = self._get_local(digest)
        if data is None:
            return None
        if self.sealer is not None:
            return self.sealer.open_evidence(data)
        return None if data.startswith(EV_MAGIC) else data
```

`_after_feed`:

```python
    def _after_feed(self, events: list[Event]) -> None:
        if self.fingerprints is None:
            return
        for ev in events:
            if ev.domain != "egress":
                continue
            if self.sealer is None and any(is_sealed(x) for x in ev.fields):
                continue                            # nothing to scan without the client key
            f = self.fields(ev.fields)
            body = self.evidence(f[7]) or b""
            found = self.fingerprints.scan(body + b" " + f[5].encode())
            if found:
                self.hits[ev.seq] = (f[8], sorted(found))
```

`src/poi/dashboard.py`:

```python
    def _evidence(self, digest: str) -> bytes | None:
        return self.m.evidence(digest)

    def _event_row(self, ev) -> dict:
        f = self.m.fields(ev.fields)
        ...  # reszta bez zmian (używa f)
```

W `_cp_stats` pętla po delcie (klucze to surowe ścieżki, wartości to ścieżki do wyświetlenia):

```python
        for op, acc, element in parse_delta(cp, raw):
            f = c.decode(element)
            if f[0] == "file":
                (adds if op == "add" else subs)[f[1]] = self.m.fields(f)[1]
            elif f[0] == "config" and op == "add":
                config = f[1]
            elif f[0] in ("egress", "dns"):
                egress += 1
                blocked += (f[8] if f[0] == "egress" else f[5]) != "allow"
        for p in sorted(adds.keys() | subs.keys()):
            key = "changed" if p in adds and p in subs else ("added" if p in adds else "removed")
            files[key].append(adds.get(p) or subs.get(p))
```

W `summary` w pętli `for ev in res.egress:` zamienić `f = ev.fields` na `f = m.fields(ev.fields)`. W `event`, w gałęzi `if ev.domain == "egress":`, zamienić `f = ev.fields` na `f = self.m.fields(ev.fields)` (bez klucza `body` jest `None`, więc `policy_recheck` się nie wykona).

`src/poi/cli.py`, `build_dashboard` — po `pubkey = ...` wstawić fragment z Task 12 (`sealer = None` / `if args.client_key: ...`), a w wywołaniu dodać `sealer=sealer`:

```python
    mirror = Mirror(Path(args.mirror), source, pubkey, fps, source_label=args.source, sealer=sealer)
```

- [ ] **Step 4: Run** `.venv/bin/pytest -m "not docker" -q` — Expected: PASS (w tym istniejące testy dashboardu i mirrora).

- [ ] **Step 5: Commit**

```bash
git add src/poi/serve.py src/poi/source.py src/poi/mirror.py src/poi/dashboard.py src/poi/cli.py \
        tests/test_serve.py tests/test_dashboard_sealed.py
git commit -m "feat(seal): sealed runs in the owner feed, mirror and dashboard

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 14: E2E z prawdziwym Dockerem

**Files:**
- Create: `tests/integration/test_sealed_e2e.py`

**Interfaces:**
- Consumes: całość. Workload `tests/integration/workload.py` (już próbuje: dozwolone wywołanie, pole z sekretem, base64 sekretu, inny host HTTP/HTTPS, bezpośredni IP, DNS exfil, zapis do `/srv/out` i `/tmp`) oraz upstream `tests/integration/upstream.py`.

- [ ] **Step 1: Write the test** — `tests/integration/test_sealed_e2e.py`

```python
"""Sealed mode end-to-end: real Docker, a leaking workload, nothing readable left behind. pytest -m docker"""
import base64
import json
import os
import threading
import time
from pathlib import Path

import pytest

docker = pytest.importorskip("docker")

from poi import daemon  # noqa: E402
from poi.cli import main  # noqa: E402
from poi.fingerprint import FingerprintSet  # noqa: E402
from poi.ledger import generate_key  # noqa: E402
from poi.runtime import Runtime, build_proxy_image  # noqa: E402
from poi.seal import bundle, keyfile  # noqa: E402
from poi.seal.grant import FP_LABEL, bundle_label, make_grant  # noqa: E402
from poi.sealed_run import SHM, SealedOptions  # noqa: E402

HERE = Path(__file__).parent
SECRET = (b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma, "
          b"address: ul. Lipowa 7, 30-001 Krakow, phone +48 600 100 200, insurer: NFZ-12-3456")
NEEDLES = [b"85010112345", b"Kowalski", b"Lipowa", base64.b64encode(SECRET[:40]),
           base64.b32encode(SECRET[:30]).decode().strip("=").lower().encode()]
FAST = {"m_kib": 1024, "t": 1, "p": 1}
pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def client():
    try:
        c = docker.from_env()
        c.ping()
    except Exception:
        pytest.skip("Docker not available")
    build_proxy_image(c)
    c.images.pull("python:3.12-slim")
    return c


@pytest.fixture(scope="module")
def sealed_run(client, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sealed")
    os.environ[keyfile.PASSWORD_ENV] = "pw"
    ckey = tmp / "client.key"
    pub = keyfile.create(ckey, "pw", **FAST)
    data = tmp / "data"
    data.mkdir()
    (data / "secret.txt").write_bytes(SECRET)
    sealed = tmp / "data.sealed"
    digest = bundle.seal_dir(data, sealed, pub)
    fp_key = b"f" * 32
    FingerprintSet.from_dir(data, fp_key).save(tmp / "fp.bin")
    (tmp / "fpk").write_bytes(fp_key)
    generate_key(tmp / "signing.key")
    run_dir = tmp / "run"
    upstream, holder = {}, {}
    real_prepare = Runtime.prepare

    def prepare_with_upstream(self, *a, **kw):
        info = real_prepare(self, *a, **kw)
        upstream["c"] = client.containers.run(
            "python:3.12-slim", ["python", "/up.py"], detach=True, name=f"poi-{info.run_id}-api",
            volumes={str(HERE / "upstream.py"): {"bind": "/up.py", "mode": "ro"}})
        client.networks.get(info.ext_network).connect(upstream["c"], aliases=["api.test"])
        return info

    spec = daemon.RunSpec(
        run_dir, HERE / "policy.yaml", tmp / "signing.key", "python:3.12-slim", ["python", "/app/workload.py"],
        (tmp / "fp.bin", None), {str(HERE / "workload.py"): "/app/workload.py"}, max_ticks=60,
        sealed=SealedOptions(pub, {str(sealed): "/data"}, ["/tmp"], allow_swap=True, grant_timeout=120))

    def run():
        try:
            holder["rt"] = daemon.start(spec, client)
        except BaseException as e:          # surface it in the test thread
            holder["err"] = e

    Runtime.prepare = prepare_with_upstream
    th = threading.Thread(target=run)
    th.start()
    try:
        deadline = time.monotonic() + 120
        while not (run_dir / "run.pub").exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        sk = keyfile.load_private(ckey, "pw")
        g = make_grant((run_dir / "run.pub").read_bytes(),
                       {bundle_label(digest): bundle.dek_for(sealed, sk), FP_LABEL: fp_key})
        (run_dir / "grant.tmp").write_bytes(g)
        os.replace(run_dir / "grant.tmp", run_dir / "grant.bin")
        th.join(timeout=300)
    finally:
        Runtime.prepare = real_prepare
        if "c" in upstream:
            upstream["c"].remove(force=True)
    assert "err" not in holder, repr(holder.get("err"))
    run_id = json.loads((run_dir / "run.pub").read_text())["run_id"]
    yield run_dir, tmp, ckey, data, digest, run_id
    os.environ.pop(keyfile.PASSWORD_ENV, None)


def _all_bytes(run_dir: Path):
    """Every file, plus the base64-decoded elements inside WAL and delta lines."""
    for p in run_dir.rglob("*"):
        if not p.is_file():
            continue
        raw = p.read_bytes()
        yield p, raw
        if p.suffix == ".jsonl":
            for line in raw.splitlines():
                d = json.loads(line)
                if "element" in d:                  # WAL and delta lines; heads.jsonl has none
                    yield p, base64.b64decode(d["element"])


def test_nothing_readable_left_on_the_host(sealed_run, client):
    run_dir, _, _, _, _, run_id = sealed_run
    for p, raw in _all_bytes(run_dir):
        for n in NEEDLES:
            assert n not in raw, f"{n!r} in {p}"
    assert not (SHM / f"poi-{run_id}").exists()
    assert client.containers.list(all=True, filters={"name": f"poi-{run_id}-"}) == []
    assert not (run_dir / "fingerprint.key").exists() and not any((run_dir / "out").iterdir())
    for p in (run_dir / "evidence").glob("*.bin"):
        raw = p.read_bytes()
        assert raw.startswith(b"POIEV1") or raw.startswith(b"{"), p      # sealed, or a config document


def test_attested_sealed_config(sealed_run):
    run_dir, _, _, _, digest, _ = sealed_run
    docs = [json.loads(p.read_bytes()) for p in (run_dir / "evidence").glob("*.bin") if p.read_bytes()[:1] == b"{"]
    s = next(d["sealed"] for d in docs if "sealed" in d)
    assert s["rootfs_ro"] is True and s["log_driver"] == "none" and "/tmp" in s["tmpfs"]
    assert s["mounts"] == {"/data": digest} and s["swap"] in (True, False)


def test_workload_result_only_for_the_client(sealed_run):
    run_dir, tmp, ckey, *_ = sealed_run
    assert main(["unseal", str(run_dir / "out.sealed"), "--key", str(ckey), "--out", str(tmp / "result")]) == 0
    r = json.loads((tmp / "result" / "result.json").read_text())
    assert r["allowed"] == 200 and r["other_host"] == 403 and r["dns_exfil"] == "failed"


def test_verify_without_and_with_client_key(sealed_run, capsys):
    run_dir, _, ckey, *_ = sealed_run
    assert main(["verify", str(run_dir)]) == 0, capsys.readouterr().err
    assert "sealed:" in capsys.readouterr().out
    assert main(["verify", str(run_dir), "--client-key", str(ckey)]) == 0, capsys.readouterr().err


def test_report_with_client_key_shows_the_attempts(sealed_run, capsys):
    run_dir, tmp, ckey, data, *_ = sealed_run
    capsys.readouterr()
    assert main(["report", str(run_dir), "--json", "--client-key", str(ckey),
                 "--data", str(data), "--fp-key", str(tmp / "fpk")]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["allowed_requests"] == 1 and r["sealed_locked"] == 0
    assert r["blocked_by_reason"].get("fingerprint", 0) == 1 and r["blocked_by_reason"].get("dns", 0) >= 1
    assert any("evil.test" in b["target"] for b in r["blocked"])
    assert r["fingerprint_hits_in_allowed_traffic"] == 0
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/integration/test_sealed_e2e.py -q` — Expected: PASS (zbuduje `poi-proxy:0.2`; potrzebny internet przy pierwszym budowaniu). Jeśli coś pada, diagnozuj przez superpowers:systematic-debugging; nie osłabiaj asercji o braku `NEEDLES`.

- [ ] **Step 3: Run the whole docker suite** `.venv/bin/pytest -m "docker and not gpu" -q` — Expected: PASS (istniejące e2e bez `--sealed` dalej działają na obrazie 0.2).

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_sealed_e2e.py
git commit -m "test(seal): docker end-to-end for sealed runs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 15: README

**Files:**
- Modify: `README.md` (nowa sekcja po „Data owner dashboard”)

- [ ] **Step 1: Add the section**

````markdown
## Sealed mode — data unreadable after the audit

With `--sealed` the client's data exists in plaintext only in RAM (tmpfs) during the run. Everything left
on the host afterwards — run directory, container, logs, backups — holds ciphertext that only the
client's password-protected key opens. Key exchange is hybrid post-quantum (X25519 + ML-KEM-768).
During the run the host is still trusted (spec §2 of `2026-10-27-poi-sealed-mode-design.md`).

Data owner, once:

```bash
poi client-keygen client.key                                   # asks for a password; writes client.pub
poi fingerprint --data moje_dane --fp-key fp.key --out fp.bin
poi seal --data moje_dane --to client.pub --out moje_dane.sealed
```

Send `client.pub`, `fp.bin` and `moje_dane.sealed` to the operator. The operator starts the run; it
writes `run/run.pub` and waits for the grant:

```bash
poi run --sealed --client-pub client.pub --sealed-mount moje_dane.sealed:/data \
        --policy examples/quickstart/policy.yaml --key signing.key --run-dir run \
        --fingerprints fp.bin --mount ./examples/quickstart/job.py:/app/job.py \
        python:3.12-slim python /app/job.py
```

The data owner turns `run.pub` into a grant (valid for this run only) and sends it back;
the operator puts it at `run/grant.bin`:

```bash
poi grant moje_dane.sealed --run-pub run.pub --key client.key --fp-key fp.key --out grant.bin
```

Afterwards anyone can check the chain (`poi verify run`); only the data owner can read content:
`poi verify run --client-key client.key`, `poi report run --client-key client.key`,
`poi dashboard ... --client-key client.key`, `poi unseal run/out.sealed --key client.key --out result`.
`POI_CLIENT_PASSWORD` supplies the password non-interactively. A policy with `require_sealed: true`
makes any run without sealed mode (or with swap active) fail verification. The run refuses to start
while swap is active unless `--allow-swap` is given; `poi clean run` wipes tmpfs leftovers of a crashed run.
````

- [ ] **Step 2: Run** `.venv/bin/pytest -m "not docker" -q && .venv/bin/pyflakes src tests` — Expected: PASS, brak ostrzeżeń.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: sealed mode in README

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
