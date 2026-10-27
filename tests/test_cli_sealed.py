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
