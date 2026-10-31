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


def test_allow_all_egress_forwards_unchanged_and_records_fingerprint(env):
    gate, tmp = env
    gate.policy = parse(POLICY + b"allow_all_egress: true\n")
    assert gate.on_connect("evil.com").verdict == "allow"
    body = b'{"note":"' + SECRET + b'"}'
    r = gate.on_request("evil.com", "PUT", "/x?y=1", [("User-Agent", "curl")], body)
    assert (r.verdict, r.reason, r.body, r.headers) == ("allow", "fingerprint", body, [("User-Agent", "curl")])
    f = c.decode(_entries(tmp)[0].element)
    assert (f[4], f[8], f[9]) == ("evil.com", "allow", "fingerprint")
    assert evidence.get(tmp / "evidence", f[7]) == body


def test_allow_all_egress_redacts_credentials_in_evidence(env):
    gate, tmp = env
    gate.policy = parse(POLICY + b"allow_all_egress: true\n")
    hdrs = [("Authorization", "Bearer sk-secret"), ("Content-Type", "application/json")]
    r = gate.on_request("api.deepseek.com", "POST", "/v1/tools", hdrs, b"{}")
    assert r.verdict == "allow" and r.headers == hdrs                    # proxy forwards the real headers
    f = c.decode(_entries(tmp)[0].element)
    assert f[6] == c.headers_digest([("Authorization", "***"), ("Content-Type", "application/json")])
    assert b"sk-secret" not in b"".join(p.read_bytes() for p in (tmp / "evidence").rglob("*") if p.is_file())


def test_isolate_kill_switch_blocks_even_open_egress(env):
    gate, tmp = env
    gate.policy = parse(POLICY + b"allow_all_egress: true\n")
    switch = [False]
    gate.isolated = lambda: switch[0]
    assert gate.on_request("evil.com", "GET", "/", [], b"").verdict == "allow"
    switch[0] = True
    assert gate.on_connect("evil.com").verdict == "block"
    r = gate.on_request(HOST, "POST", PATH, [("Authorization", "Bearer x")], b'{"model":"small","count":1}')
    assert (r.verdict, r.reason) == ("block", "isolated")
    assert [c.decode(e.element)[9] for e in _entries(tmp)][-1] == "isolated"
