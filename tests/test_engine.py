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
