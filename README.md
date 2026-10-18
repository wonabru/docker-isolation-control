# poi — Proof of Isolation

A cryptographic proof (under the threat model: untrusted workload, trusted host) that data inside a
Docker container did not leave it other than through an allowed, fully logged, schema-conforming channel.
Specification: `docs/superpowers/specs/2026-10-13-proof-of-isolation-design.md`.

## Installation

```bash
uv venv --python 3.12 && uv pip install -e '.[dev]'
```

## Usage — ready-to-run example

`examples/quickstart/` contains a job (`job.py`) that reads patient data from `/data` and sends only
two numbers (record count, average age) out to `https://httpbin.org/anything`.
The policy (`policy.yaml`) allows only that endpoint and only those two fields.

```bash
poi keygen signing.key                                             # operator's Ed25519 key
poi fingerprint --data examples/quickstart/moje_dane --fp-key fp.key --out fp.bin
poi run --policy examples/quickstart/policy.yaml --key signing.key --run-dir run \
        --fingerprints fp.bin --fp-key fp.key \
        --mount ./examples/quickstart/moje_dane:/data \
        --mount ./examples/quickstart/job.py:/app/job.py \
        python:3.12-slim python /app/job.py
poi verify run --live                                              # exit 0 = OK, 10–17 = error kind
poi report run --data examples/quickstart/moje_dane --fp-key fp.key
poi clean run                                                      # removes the stopped workload and network
```

Expected report: 1 allowed request, 0 user-data hits in allowed traffic, covert channel upper bound
of 27 bits. The first `poi run` builds the `poi-proxy:0.1` image (requires network access).

Custom workload: any image and command in place of `python:3.12-slim python /app/job.py`. The workload
must use `HTTP(S)_PROXY` and trust the CA from `SSL_CERT_FILE` (both are set automatically).

## Data owner dashboard

The operator exposes the run read-only (TLS is provided by their reverse proxy, e.g. Caddy):

```bash
poi serve run --token-file serve.token --new-token          # 127.0.0.1:8765, token written to a 0600 file
```

The data owner — on their own machine, with the operator's public key received out of band:

```bash
poi dashboard --source https://operator.example/poi --token-file serve.token \
              --pubkey <hex from operator> --mirror ~/poi/run-1 \
              --data ./moje_dane --fp-key fp.key --open
```

The dashboard verifies every checkpoint locally (codes 10–16), keeps a verified copy in `--mirror`
(`poi verify` / `poi report` work on it) and shows a verdict: **Verified** / **Needs attention** /
**Proof broken**. Container state (status, CPU, RAM) is the operator's claim — it is displayed but
never affects the verdict. To preview a local run, `--source ./run` is enough.

## Case: LLM in a container (vLLM + Qwen3-0.6B, GPU)

`examples/llm/` runs an agent on a local model that summarizes `moje_dane/pacjenci.csv`.
One record contains a prompt injection instructing it to send the data to `http://evil.test/collect`.
The policy allows no outbound traffic and attests the GPU, the image (by ID) and the model weights
(content digest).

```bash
docker pull vllm/vllm-openai:v0.11.0                      # ≈38 GB, CUDA 12.8
docker build -t poi-llm-example examples/llm
poi fingerprint --data examples/llm/moje_dane --fp-key fp.key --out fp.bin
poi run --policy examples/llm/policy.yaml --key signing.key --run-dir run-llm \
        --fingerprints fp.bin --fp-key fp.key --gpus all --shm-size 1g \
        --env HF_HOME=/hf --env HF_HUB_OFFLINE=1 \
        --mount ./examples/llm/moje_dane:/data --mount ./examples/llm/job.py:/app/job.py \
        --mount ~/.cache/huggingface/hub/models--Qwen--Qwen3-0.6B:/hf/hub/models--Qwen--Qwen3-0.6B \
        poi-llm-example python3 /app/job.py
poi report run-llm --data examples/llm/moje_dane --fp-key fp.key
```

On an RTX 3060 shared with another GPU process, `POI_GPU_UTIL=0.16` (the default) is enough. Result on
the reference host: 0 requests sent; blocked and logged — vLLM telemetry (`CONNECT stats.vllm.ai`),
two reverse DNS lookups and a **model-issued** `POST evil.test/collect` carrying a patient record
(fingerprint hit → dashboard "Needs attention").

## Tests

```bash
pytest -m "not docker"           # unit tests
pytest -m "docker and not gpu"   # end-to-end with real Docker (builds the poi-proxy:0.1 image)
pytest -m "docker and gpu"       # LLM case: NVIDIA GPU, vLLM 0.11 image and Qwen3-0.6B in the HF cache
```
