import os
import threading
import time
from pathlib import Path

import pytest

from poi import canonical as c
from poi import daemon
from poi.seal import SealError, bundle, kem
from poi.seal.grant import FP_LABEL, bundle_label, make_grant
from poi.seal.sealer import open_sealed_doc
from poi.sealed_run import SealedOptions, SealedSession, run_id_of, swap_active, wipe_dir

HEADER = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"


def test_swap_active(tmp_path):
    p = tmp_path / "swaps"
    p.write_text(HEADER)
    assert not swap_active(p)
    p.write_text(HEADER + "/swapfile file 1024 0 -2\n")
    assert swap_active(p)


def test_swap_refused_before_anything_is_written(tmp_path):
    s = SealedSession(tmp_path / "run", SealedOptions(b"", {}), shm_root=tmp_path / "shm", swap=True)
    with pytest.raises(SealError, match="swap"):
        s.setup(False)
    assert not (tmp_path / "shm").exists() and not (tmp_path / "run" / "run.pub").exists()


def _send_grant(run: Path, keys_for):
    p = run / "run.pub"
    while not p.exists():
        time.sleep(0.05)
    g = make_grant(p.read_bytes(), keys_for())
    (run / "grant.tmp").write_bytes(g)
    os.replace(run / "grant.tmp", run / "grant.bin")


def test_session_lifecycle(tmp_path):
    csk, cpk = kem.generate()
    data = tmp_path / "data"
    data.mkdir()
    (data / "secret.txt").write_bytes(b"85010112345")
    b = tmp_path / "d.sealed"
    digest = bundle.seal_dir(data, b, cpk)
    run = tmp_path / "run"
    s = SealedSession(run, SealedOptions(cpk, {str(b): "/data"}, grant_timeout=30), run_id="r1",
                      shm_root=tmp_path / "shm", swap=False)
    th = threading.Thread(target=_send_grant, args=(run, lambda: {
        bundle_label(digest): bundle.dek_for(b, csk), FP_LABEL: b"f" * 32}))
    th.start()
    s.setup(want_fingerprint_key=True)
    th.join()

    assert run_id_of(run) == "r1"
    (src, target), = s.ro_mounts.items()
    assert target == "/data" and Path(src).is_relative_to(tmp_path / "shm" / "poi-r1")
    assert (Path(src) / "secret.txt").read_bytes() == b"85010112345"
    assert (tmp_path / "shm" / "poi-r1").stat().st_mode & 0o777 == 0o700
    assert (s.secrets / "fingerprint.key").read_bytes() == b"f" * 32 and len((s.secrets / "ek").read_bytes()) == 32
    owner = open_sealed_doc((run / "sealed.json").read_bytes(), csk)
    assert owner.open_evidence(s.sealer.seal_evidence(b"x")) == b"x"
    info = s.config_info("/srv/out")
    assert info == {"client_pub": c.b2b256(cpk), "run_pub": c.b2b256((run / "run.pub").read_bytes()),
                    "mounts": {"/data": digest}, "swap": False, "out_target": "/srv/out"}

    (s.out / "result.json").write_bytes(b"42")
    sealed_out = s.finish()
    assert sealed_out == run / "out.sealed"
    bundle.unseal_to(sealed_out, bundle.dek_for(sealed_out, csk), tmp_path / "o")
    assert (tmp_path / "o" / "result.json").read_bytes() == b"42"
    s.wipe()
    assert not (tmp_path / "shm" / "poi-r1").exists() and s.sealer is None
    assert not any(b"85010112345" in p.read_bytes() for p in run.rglob("*") if p.is_file())


def test_finish_without_output_writes_nothing(tmp_path):
    s = SealedSession(tmp_path / "run", SealedOptions(b"", {}), run_id="r2", shm_root=tmp_path, swap=False)
    s.out.mkdir(parents=True)
    assert s.finish() is None


def test_wipe_dir_falls_back_to_root_rm(tmp_path):
    d = tmp_path / "w"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "f").write_bytes(b"secret")
    os.chmod(d / "sub", 0o500)                     # like a root-owned dir: contents cannot be removed
    calls = []

    def fake_root_rm(p):
        calls.append(p)
        os.chmod(p / "sub", 0o700)
        for x in (p / "sub").iterdir():
            x.unlink()
    wipe_dir(d, fake_root_rm)
    assert not d.exists()
    assert calls == [d] or os.geteuid() == 0      # root can remove it without the fallback


def test_resume_refuses_sealed_run(tmp_path):
    (tmp_path / "sealed.json").write_text("{}")
    with pytest.raises(SealError, match="cannot be resumed"):
        daemon.resume(tmp_path, tmp_path / "k", client=object())
