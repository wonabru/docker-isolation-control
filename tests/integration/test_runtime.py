"""Docker smoke test for the runtime layer. Run with: pytest -m docker"""
from pathlib import Path

import pytest

docker = pytest.importorskip("docker")

from poi.runtime import Runtime, build_proxy_image  # noqa: E402

HERE = Path(__file__).parent
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


def test_prepare_creates_isolated_topology(client, tmp_path):
    rt = Runtime(client, tmp_path / "run")
    info = rt.prepare(HERE / "policy.yaml")
    try:
        assert (tmp_path / "run" / "ca" / "mitmproxy-ca-cert.pem").exists()
        assert client.networks.get(info.int_network).attrs["Internal"] is True
        assert info.proxy_ip.startswith("10.231.") and info.proxy_ip.endswith(".2")
        w = rt.create_workload("python:3.12-slim", ["true"], "/srv/out")
        w.reload()
        assert list(w.attrs["NetworkSettings"]["Networks"]) == [info.int_network]
        assert w.attrs["HostConfig"]["Dns"] == [info.proxy_ip]
    finally:
        rt.teardown(keep_workload=False)
    names = {n.name for n in client.networks.list()}
    assert info.int_network not in names and info.ext_network not in names
