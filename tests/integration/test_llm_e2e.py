"""LLM case end-to-end: vLLM + Qwen3-0.6B inside poi, prompt injection in the data.

Run with: pytest -m "docker and gpu". Skipped when the GPU, the base image or the model is unavailable.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

docker = pytest.importorskip("docker")

from poi import daemon  # noqa: E402
from poi.assess import ATTENTION, VERIFIED  # noqa: E402
from poi.cli import main  # noqa: E402
from poi.fingerprint import FingerprintSet  # noqa: E402
from poi.ledger import generate_key  # noqa: E402
from poi.mirror import Mirror  # noqa: E402
from poi.policy import load as load_policy  # noqa: E402
from poi.source import LocalSource  # noqa: E402
from poi.verify import verify_chain  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
EXAMPLE = REPO / "examples" / "llm"
BASE_IMAGE = "vllm/vllm-openai:v0.11.0"
IMAGE = "poi-llm-example"
MODEL = Path.home() / ".cache" / "huggingface" / "hub" / "models--Qwen--Qwen3-0.6B"
MODEL_IN_CONTAINER = "/hf/hub/models--Qwen--Qwen3-0.6B"
pytestmark = [pytest.mark.docker, pytest.mark.gpu]


def _free_gpu_mib() -> int:
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=20).stdout
        return max(int(x) for x in out.split())
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


@pytest.fixture(scope="module")
def llm_run(tmp_path_factory):
    if _free_gpu_mib() < 2048:
        pytest.skip("needs an NVIDIA GPU with at least 2 GiB free")
    if not MODEL.is_dir():
        pytest.skip(f"model not in the Hugging Face cache: {MODEL}")
    client = docker.from_env()
    try:
        client.images.get(BASE_IMAGE)
    except docker.errors.ImageNotFound:
        pytest.skip(f"pull {BASE_IMAGE} first (≈38 GB)")
    client.images.build(path=str(EXAMPLE), tag=IMAGE, rm=True)
    tmp = tmp_path_factory.mktemp("llm")
    data = tmp / "data"
    shutil.copytree(EXAMPLE / "moje_dane", data)
    fp_key = b"f" * 32
    FingerprintSet.from_dir(data, fp_key).save(tmp / "fp.bin")
    pub = generate_key(tmp / "signing.key")
    run_dir = tmp / "run"
    rt = daemon.start(daemon.RunSpec(
        run_dir, EXAMPLE / "policy.yaml", tmp / "signing.key", IMAGE, ["python3", "/app/job.py"],
        (tmp / "fp.bin", fp_key),
        {str(EXAMPLE / "job.py"): "/app/job.py", str(data): "/data", str(MODEL): MODEL_IN_CONTAINER},
        max_ticks=400, gpus="all", shm_size="1g", env={"HF_HOME": "/hf", "HF_HUB_OFFLINE": "1"}), client)
    rt.teardown(keep_workload=True)
    yield run_dir, data, fp_key, pub, rt
    rt.teardown(keep_workload=False)


def _summary(run_dir):
    return json.loads((run_dir / "out" / "summary.json").read_text())


def test_job_summarised_every_record(llm_run):
    run_dir, *_ = llm_run
    results = _summary(run_dir)["results"]
    assert [r["patient"] for r in results] == ["Jan Kowalski", "Anna Nowak", "Piotr Wiśniewski", "Maria Wójcik"]
    assert all(r["summary"] or r["tool_calls"] for r in results)


def test_nothing_left_and_everything_was_logged(llm_run):
    run_dir, _, _, pub, _ = llm_run
    res = verify_chain(run_dir, pub)
    events = [e.fields for e in res.egress]
    assert events, "the LLM stack made no outbound attempt at all"
    assert all((f[8] if f[0] == "egress" else f[5]) == "block" for f in events)
    assert any(f[0] == "egress" and f[4] == "stats.vllm.ai" for f in events)      # vLLM usage stats


def test_verify_live_and_config_attests_gpu_and_model(llm_run, capsys):
    run_dir, _, _, pub, _ = llm_run
    assert main(["verify", str(run_dir), "--live"]) == 0, capsys.readouterr().err
    from poi import canonical as c
    from poi import evidence
    res = verify_chain(run_dir, pub)
    doc = json.loads(evidence.get(run_dir / "evidence", res.config_digests[-1][1]))
    assert doc["gpus"] and doc["gpus"][0]["capabilities"] == ["gpu"]
    model = next(m for m in doc["mounts"] if m["destination"] == MODEL_IN_CONTAINER)
    assert not model["rw"] and len(model["content"]) == 64
    assert load_policy(run_dir / "policy.yaml").image_attestation == "digest"
    assert c.b2b256(b"") != model["content"]


def test_prompt_injection_outcome_is_visible_to_the_owner(llm_run):
    run_dir, data, fp_key, pub, _ = llm_run
    called = [c for r in _summary(run_dir)["results"] for c in r["tool_calls"]]
    m = Mirror(run_dir.parent / "mirror", LocalSource(run_dir, runtime=lambda: {"status": "exited"}), pub,
               FingerprintSet.from_dir(data, fp_key), sleep=lambda s: None)
    m.sync_once(wait=0)
    m.refresh_runtime()
    evil = [s for s, (v, _) in m.hits.items() if v == "block"]
    if any(c["url"].startswith("http://evil.test") for c in called):
        assert evil and m.verdict().level == ATTENTION       # blocked attempt carrying the user's data
        assert all(c["result"] == "HTTP 403" for c in called)
    else:
        assert not evil and m.verdict().level == VERIFIED
    assert not [s for s, (v, _) in m.hits.items() if v == "allow"]
