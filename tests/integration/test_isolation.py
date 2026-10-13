"""End-to-end: real Docker, real proxy, a workload that tries to leak. Run with: pytest -m docker"""
import json
from pathlib import Path

import pytest

docker = pytest.importorskip("docker")

from poi import daemon  # noqa: E402
from poi.cli import main  # noqa: E402
from poi.fingerprint import FingerprintSet  # noqa: E402
from poi.ledger import generate_key  # noqa: E402
from poi.runtime import Runtime, build_proxy_image  # noqa: E402

HERE = Path(__file__).parent
SECRET = (b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma, "
          b"address: ul. Lipowa 7, 30-001 Krakow, phone +48 600 100 200, insurer: NFZ-12-3456")

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def client():
    try:
        c = docker.from_env()
        c.ping()
    except Exception:
        pytest.skip("Docker not available")
    build_proxy_image(c)
    for img in ("python:3.12-slim",):
        c.images.pull(img)
    return c


@pytest.fixture(scope="module")
def finished_run(client, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("poi")
    data = tmp / "data"
    data.mkdir()
    (data / "secret.txt").write_bytes(SECRET)
    fp_key = b"f" * 32
    FingerprintSet.from_dir(data, fp_key).save(tmp / "fp.bin")
    generate_key(tmp / "signing.key")
    run_dir = tmp / "run"

    upstream = {}
    real_prepare = Runtime.prepare

    def prepare_with_upstream(self, *a, **kw):
        info = real_prepare(self, *a, **kw)
        upstream["c"] = client.containers.run(
            "python:3.12-slim", ["python", "/up.py"], detach=True, name=f"poi-{info.run_id}-api",
            volumes={str(HERE / "upstream.py"): {"bind": "/up.py", "mode": "ro"}})
        client.networks.get(info.ext_network).connect(upstream["c"], aliases=["api.test"])
        return info

    Runtime.prepare = prepare_with_upstream
    try:
        rt = daemon.start(daemon.RunSpec(
            run_dir, HERE / "policy.yaml", tmp / "signing.key", "python:3.12-slim",
            ["python", "/app/workload.py"], (tmp / "fp.bin", fp_key),
            {str(HERE / "workload.py"): "/app/workload.py", str(data): "/data"}, max_ticks=60), client)
    finally:
        Runtime.prepare = real_prepare
    logs = rt.workload().logs().decode()
    upstream["c"].remove(force=True)
    rt.teardown(keep_workload=True)
    yield run_dir, data, tmp, logs
    rt.teardown(keep_workload=False)


def test_workload_saw_only_the_allowed_call_succeed(finished_run):
    run_dir, _, _, logs = finished_run
    r = json.loads(logs.strip().splitlines()[-1])
    assert r["allowed"] == 200
    assert r["extra_field"] == 403
    assert r["note_base64_secret"] == 403
    assert r["other_host"] == 403
    assert r["https_other_host"] != 200
    assert r["direct_ip"] == "unreachable"
    assert r["dns_exfil"] == "failed"


def test_verify_passes_including_live(finished_run, capsys):
    run_dir, *_ = finished_run
    assert main(["verify", str(run_dir), "--live"]) == 0, capsys.readouterr().err


def test_report_lists_every_attempt(finished_run, capsys):
    run_dir, data, tmp, _ = finished_run
    capsys.readouterr()
    assert main(["report", str(run_dir), "--json", "--data", str(data),
                 "--fp-key", str(_write(tmp / "fpk", b"f" * 32))]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["allowed_requests"] == 1
    reasons = r["blocked_by_reason"]
    assert reasons.get("schema", 0) >= 1
    assert reasons.get("fingerprint", 0) == 1
    assert reasons.get("host-not-allowed", 0) >= 2      # plain HTTP + CONNECT
    assert reasons.get("dns", 0) >= 1
    assert r["fingerprint_hits_in_allowed_traffic"] == 0
    assert any(h["verdict"] == "block" for h in r["fingerprint_hits"])


def test_tampering_with_the_run_is_detected(finished_run, tmp_path):
    import shutil
    run_dir, *_ = finished_run
    copy = tmp_path / "run"
    shutil.copytree(run_dir, copy)
    ev = sorted((copy / "evidence").glob("*.bin"))[0]
    ev.write_bytes(ev.read_bytes() + b"x")
    assert main(["verify", str(copy)]) != 0


def _write(p: Path, b: bytes) -> Path:
    p.write_bytes(b)
    return p
