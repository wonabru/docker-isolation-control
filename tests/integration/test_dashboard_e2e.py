"""Live end-to-end: poi run + poi serve + owner-side Mirror over HTTP. Run with: pytest -m docker"""
import threading
import time
from pathlib import Path

import pytest

docker = pytest.importorskip("docker")

from poi import daemon  # noqa: E402
from poi.assess import ATTENTION, VERIFIED  # noqa: E402
from poi.fingerprint import FingerprintSet  # noqa: E402
from poi.ledger import generate_key  # noqa: E402
from poi.mirror import Mirror  # noqa: E402
from poi.runtime import Runtime, build_proxy_image  # noqa: E402
from poi.serve import make_server  # noqa: E402
from poi.source import HttpSource  # noqa: E402

HERE = Path(__file__).parent
SECRET = (b"patient: Jan Kowalski, PESEL 85010112345, diagnosis: J45.0 asthma, "
          b"address: ul. Lipowa 7, 30-001 Krakow, phone +48 600 100 200")
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


def test_dashboard_follows_a_live_run(client, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "secret.txt").write_bytes(SECRET)
    fp_key = b"f" * 32
    FingerprintSet.from_dir(data, fp_key).save(tmp_path / "fp.bin")
    pub = generate_key(tmp_path / "signing.key")
    run_dir = tmp_path / "run"
    holder = {}
    real_prepare = Runtime.prepare

    def prepare_with_upstream_and_feed(self, *a, **kw):
        info = real_prepare(self, *a, **kw)
        holder["api"] = client.containers.run(
            "python:3.12-slim", ["python", "/up.py"], detach=True, name=f"poi-{info.run_id}-api",
            volumes={str(HERE / "upstream.py"): {"bind": "/up.py", "mode": "ro"}})
        client.networks.get(info.ext_network).connect(holder["api"], aliases=["api.test"])
        srv = make_server(self.run_dir, "tok", port=0, poll=0.1)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        holder["srv"] = srv
        return info

    Runtime.prepare = prepare_with_upstream_and_feed
    runner = threading.Thread(target=lambda: holder.update(rt=daemon.start(daemon.RunSpec(
        run_dir, HERE / "policy.yaml", tmp_path / "signing.key", "python:3.12-slim",
        ["python", "/app/w.py"], (tmp_path / "fp.bin", fp_key),
        {str(HERE / "workload_slow.py"): "/app/w.py", str(data): "/data"}, max_ticks=60), client)))
    try:
        runner.start()
        deadline = time.monotonic() + 120
        while "srv" not in holder and time.monotonic() < deadline:
            time.sleep(0.2)
        source = HttpSource(f"http://127.0.0.1:{holder['srv'].server_address[1]}", "tok")
        fps = FingerprintSet.from_dir(data, fp_key)
        while not (run_dir / "ledger" / "000000.json").exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        mirror = Mirror(tmp_path / "mirror", source, pub, fps, sleep=lambda s: None)
        levels = []
        while runner.is_alive() and time.monotonic() < deadline:
            mirror.sync_once(wait=1)
            levels.append(mirror.verdict().level)
        mirror.sync_once(wait=0)
    finally:
        Runtime.prepare = real_prepare
        runner.join(timeout=30)
        if "srv" in holder:
            holder["srv"].shutdown()
        if "api" in holder:
            holder["api"].remove(force=True)
        if "rt" in holder:
            holder["rt"].teardown(keep_workload=False)

    assert VERIFIED in levels, levels
    assert levels.index(VERIFIED) < levels.index(ATTENTION), levels
    assert mirror.verdict().level == ATTENTION and mirror.error is None
    seq = next(s for s, (v, _) in mirror.hits.items() if v == "block")
    assert mirror.ack(seq) and mirror.verdict().level == VERIFIED
