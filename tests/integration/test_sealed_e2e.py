"""Sealed mode end-to-end: real Docker, a leaking workload, nothing readable left behind. pytest -m docker"""
import base64
import json
import os
import threading
import time
from pathlib import Path

import pytest

docker = pytest.importorskip("docker")

from poi import daemon  # noqa: E402
from poi.cli import main  # noqa: E402
from poi.fingerprint import FingerprintSet  # noqa: E402
from poi.ledger import generate_key  # noqa: E402
from poi.runtime import Runtime, build_proxy_image  # noqa: E402
from poi.seal import bundle, keyfile  # noqa: E402
from poi.seal.grant import FP_LABEL, bundle_label, make_grant  # noqa: E402
from poi.sealed_run import SHM, SealedOptions  # noqa: E402

HERE = Path(__file__).parent
SECRET = (b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma, "
          b"address: ul. Lipowa 7, 30-001 Krakow, phone +48 600 100 200, insurer: NFZ-12-3456")
NEEDLES = [b"85010112345", b"Kowalski", b"Lipowa", base64.b64encode(SECRET[:40]),
           base64.b32encode(SECRET[:30]).decode().strip("=").lower().encode()]
FAST = {"m_kib": 1024, "t": 1, "p": 1}
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


@pytest.fixture(scope="module")
def sealed_run(client, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sealed")
    os.environ[keyfile.PASSWORD_ENV] = "pw"
    ckey = tmp / "client.key"
    pub = keyfile.create(ckey, "pw", **FAST)
    data = tmp / "data"
    data.mkdir()
    (data / "secret.txt").write_bytes(SECRET)
    sealed = tmp / "data.sealed"
    digest = bundle.seal_dir(data, sealed, pub)
    fp_key = b"f" * 32
    FingerprintSet.from_dir(data, fp_key).save(tmp / "fp.bin")
    (tmp / "fpk").write_bytes(fp_key)
    generate_key(tmp / "signing.key")
    run_dir = tmp / "run"
    upstream, holder = {}, {}
    real_prepare, real_teardown = Runtime.prepare, Runtime.teardown

    def prepare_with_upstream(self, *a, **kw):
        info = real_prepare(self, *a, **kw)
        upstream["c"] = client.containers.run(
            "python:3.12-slim", ["python", "/up.py"], detach=True, name=f"poi-{info.run_id}-api",
            volumes={str(HERE / "upstream.py"): {"bind": "/up.py", "mode": "ro"}})
        client.networks.get(info.ext_network).connect(upstream["c"], aliases=["api.test"])
        return info

    def teardown_after_upstream(self, *a, **kw):    # the upstream is attached to the run's ext network
        if "c" in upstream:
            upstream.pop("c").remove(force=True)
        return real_teardown(self, *a, **kw)

    spec = daemon.RunSpec(
        run_dir, HERE / "policy.yaml", tmp / "signing.key", "python:3.12-slim", ["python", "/app/workload.py"],
        (tmp / "fp.bin", None), {str(HERE / "workload.py"): "/app/workload.py"}, max_ticks=60,
        sealed=SealedOptions(pub, {str(sealed): "/data"}, ["/tmp"], allow_swap=True, grant_timeout=120))

    def run():
        try:
            holder["rt"] = daemon.start(spec, client)
        except BaseException as e:          # surface it in the test thread
            holder["err"] = e

    Runtime.prepare, Runtime.teardown = prepare_with_upstream, teardown_after_upstream
    th = threading.Thread(target=run)
    th.start()
    try:
        deadline = time.monotonic() + 120
        while not (run_dir / "run.pub").exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        sk = keyfile.load_private(ckey, "pw")
        g = make_grant((run_dir / "run.pub").read_bytes(),
                       {bundle_label(digest): bundle.dek_for(sealed, sk), FP_LABEL: fp_key})
        (run_dir / "grant.tmp").write_bytes(g)
        os.replace(run_dir / "grant.tmp", run_dir / "grant.bin")
        th.join(timeout=300)
    finally:
        Runtime.prepare, Runtime.teardown = real_prepare, real_teardown
        if "c" in upstream:
            upstream["c"].remove(force=True)
    assert "err" not in holder, repr(holder.get("err"))
    run_id = json.loads((run_dir / "run.pub").read_text())["run_id"]
    yield run_dir, tmp, ckey, data, digest, run_id
    os.environ.pop(keyfile.PASSWORD_ENV, None)


def _all_bytes(run_dir: Path):
    """Every file, plus the base64-decoded elements inside WAL and delta lines."""
    for p in run_dir.rglob("*"):
        if not p.is_file():
            continue
        raw = p.read_bytes()
        yield p, raw
        if p.suffix == ".jsonl":
            for line in raw.splitlines():
                d = json.loads(line)
                if "element" in d:                  # WAL and delta lines; heads.jsonl has none
                    yield p, base64.b64decode(d["element"])


def test_nothing_readable_left_on_the_host(sealed_run, client):
    run_dir, _, _, _, _, run_id = sealed_run
    for p, raw in _all_bytes(run_dir):
        for n in NEEDLES:
            assert n not in raw, f"{n!r} in {p}"
    assert not (SHM / f"poi-{run_id}").exists()
    assert client.containers.list(all=True, filters={"name": f"poi-{run_id}-"}) == []
    assert not (run_dir / "fingerprint.key").exists() and not any((run_dir / "out").iterdir())
    for p in (run_dir / "evidence").glob("*.bin"):
        raw = p.read_bytes()
        assert raw.startswith(b"POIEV1") or raw.startswith(b"{"), p      # sealed, or a config document


def test_attested_sealed_config(sealed_run):
    run_dir, _, _, _, digest, _ = sealed_run
    docs = [json.loads(p.read_bytes()) for p in (run_dir / "evidence").glob("*.bin") if p.read_bytes()[:1] == b"{"]
    s = next(d["sealed"] for d in docs if "sealed" in d)
    assert s["rootfs_ro"] is True and s["log_driver"] == "none" and "/tmp" in s["tmpfs"]
    assert s["mounts"] == {"/data": digest} and s["swap"] in (True, False)


def test_workload_result_only_for_the_client(sealed_run):
    run_dir, tmp, ckey, *_ = sealed_run
    assert main(["unseal", str(run_dir / "out.sealed"), "--key", str(ckey), "--out", str(tmp / "result")]) == 0
    r = json.loads((tmp / "result" / "result.json").read_text())
    assert r["allowed"] == 200 and r["other_host"] == 403 and r["dns_exfil"] == "failed"


def test_verify_without_and_with_client_key(sealed_run, capsys):
    run_dir, _, ckey, *_ = sealed_run
    assert main(["verify", str(run_dir)]) == 0, capsys.readouterr().err
    assert "sealed:" in capsys.readouterr().out
    assert main(["verify", str(run_dir), "--client-key", str(ckey)]) == 0, capsys.readouterr().err


def test_report_with_client_key_shows_the_attempts(sealed_run, capsys):
    run_dir, tmp, ckey, data, *_ = sealed_run
    capsys.readouterr()
    assert main(["report", str(run_dir), "--json", "--client-key", str(ckey),
                 "--data", str(data), "--fp-key", str(tmp / "fpk")]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["allowed_requests"] == 1 and r["sealed_locked"] == 0
    assert r["blocked_by_reason"].get("fingerprint", 0) == 1 and r["blocked_by_reason"].get("dns", 0) >= 1
    assert any("evil.test" in b["target"] for b in r["blocked"])
    assert r["fingerprint_hits_in_allowed_traffic"] == 0
