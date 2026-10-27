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
