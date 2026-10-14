from pathlib import Path

from poi import cli, daemon
from poi.runtime import CA_IN_WORKLOAD, Runtime, RuntimeInfo


class _Containers:
    def __init__(self):
        self.kwargs = None

    def create(self, image, **kw):
        self.kwargs = kw

        class W:
            id = "w1"
        return W()


class _Client:
    def __init__(self):
        self.containers = _Containers()


def test_create_workload_gpu_shm_env(tmp_path):
    client = _Client()
    rt = Runtime(client, tmp_path, RuntimeInfo("r1", "int", "ext", "10.231.0.2"))
    rt.create_workload("img", ["python", "/app/job.py"], "/srv/out", {str(tmp_path): "/hf"},
                       gpus="all", shm_size="1g", env={"HF_HUB_OFFLINE": "1", "HTTP_PROXY": "evil"})
    kw = client.containers.kwargs
    req = kw["device_requests"][0]
    assert (req["Count"], req["Capabilities"]) == (-1, [["gpu"]])
    assert kw["shm_size"] == "1g"
    assert kw["environment"]["HF_HUB_OFFLINE"] == "1"
    assert kw["environment"]["HTTP_PROXY"] == "http://10.231.0.2:8080"     # poi's proxy always wins
    assert kw["environment"]["SSL_CERT_FILE"] == CA_IN_WORKLOAD
    assert kw["volumes"][str(tmp_path.resolve())] == {"bind": "/hf", "mode": "ro"}


def test_create_workload_without_options_has_no_gpu(tmp_path):
    client = _Client()
    Runtime(client, tmp_path, RuntimeInfo("r1", "int", "ext", "10.231.0.2")).create_workload("img", None, None)
    assert "device_requests" not in client.containers.kwargs and "shm_size" not in client.containers.kwargs


def test_cli_run_passes_llm_options(monkeypatch, tmp_path):
    seen = {}

    class RT:
        def teardown(self, keep_workload):
            pass

    monkeypatch.setattr(daemon, "start", lambda spec: seen.setdefault("spec", spec) and RT() or RT())
    assert cli.main(["run", "--policy", "p.yaml", "--key", "k", "--run-dir", str(tmp_path),
                     "--gpus", "all", "--shm-size", "1g", "--env", "HF_HUB_OFFLINE=1", "--env", "A=b=c",
                     "--mount", "/models:/hf", "img", "python", "/app/job.py"]) == 0
    spec = seen["spec"]
    assert (spec.gpus, spec.shm_size) == ("all", "1g")
    assert spec.env == {"HF_HUB_OFFLINE": "1", "A": "b=c"}
    assert spec.extra_ro_mounts == {"/models": "/hf"} and spec.command == ["python", "/app/job.py"]
    assert spec.run_dir == Path(tmp_path)
