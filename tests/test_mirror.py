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
