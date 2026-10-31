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


ALLOW_ALL = POLICY + b"allow_all_egress: true\n"


def _open_run(tmp_path, key, policy):
    eng, gate = _engine(tmp_path, key, FakeFS(IMAGE, MOUNTS), policy=policy)
    eng.genesis()
    gate.policy = parse(policy)
    r = gate.on_request("evil.com", "PUT", "/upload?x=1", [("user-agent", "curl")], b"raw bytes")
    gate.on_response(r.seq, 200, [], b"ok")
    gate.wal.record_dns("2026-10-13T18:00:00Z", "evil.com", "A", "allow")
    eng.tick()
    return tmp_path / "run"


def test_allow_all_egress_run_passes_with_its_policy(tmp_path, key):
    _check(_open_run(tmp_path, key, ALLOW_ALL), key, ALLOW_ALL)


def test_open_traffic_rejected_without_allow_all(tmp_path, key):
    run = _open_run(tmp_path, key, ALLOW_ALL)
    res = verify_chain(run, pubkey_hex(key))
    p = parse(POLICY)
    p.raw = parse(ALLOW_ALL).raw              # same digest, but the flag is off: traffic must not pass
    with pytest.raises(VerifyError) as ei:
        verify_policy(res, run, p)
    assert ei.value.code == E_SCHEMA
