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
