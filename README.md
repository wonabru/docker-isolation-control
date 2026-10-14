# poi — Proof of Isolation

Kryptograficzny dowód (przy modelu zagrożeń: niezaufany workload, zaufany host), że dane w kontenerze
Docker nie opuściły go inaczej niż przez dozwolony, w pełni zalogowany i zgodny ze schematem kanał.
Specyfikacja: `docs/superpowers/specs/2026-10-13-proof-of-isolation-design.md`.

## Instalacja

```bash
uv venv --python 3.12 && uv pip install -e '.[dev]'
```

## Użycie — przykład gotowy do uruchomienia

`examples/quickstart/` zawiera zadanie (`job.py`), które czyta dane pacjentów z `/data` i wysyła na
zewnątrz wyłącznie dwie liczby (liczba rekordów, średni wiek) do `https://httpbin.org/anything`.
Polityka (`policy.yaml`) dopuszcza tylko ten endpoint i tylko te dwa pola.

```bash
poi keygen signing.key                                             # klucz Ed25519 operatora
poi fingerprint --data examples/quickstart/moje_dane --fp-key fp.key --out fp.bin
poi run --policy examples/quickstart/policy.yaml --key signing.key --run-dir run \
        --fingerprints fp.bin --fp-key fp.key \
        --mount ./examples/quickstart/moje_dane:/data \
        --mount ./examples/quickstart/job.py:/app/job.py \
        python:3.12-slim python /app/job.py
poi verify run --live                                              # kod 0 = OK, 10–17 = rodzaj błędu
poi report run --data examples/quickstart/moje_dane --fp-key fp.key
poi clean run                                                      # usuwa zatrzymany workload i sieć
```

Oczekiwany raport: 1 dozwolone żądanie, 0 trafień danych użytkownika w ruchu dozwolonym, górne
ograniczenie kanału ukrytego 27 bitów. Pierwsze `poi run` buduje obraz `poi-proxy:0.1` (wymaga sieci).

Własny workload: dowolny obraz i komenda zamiast `python:3.12-slim python /app/job.py`. Workload musi
korzystać z `HTTP(S)_PROXY` i ufać CA z `SSL_CERT_FILE` (oba ustawiane automatycznie).

## Dashboard właściciela danych

Operator udostępnia przebieg tylko do odczytu (TLS zapewnia jego reverse proxy, np. Caddy):

```bash
poi serve run --token-file serve.token --new-token          # 127.0.0.1:8765, token do pliku 0600
```

Właściciel danych — na swojej maszynie, z kluczem publicznym operatora otrzymanym inną drogą:

```bash
poi dashboard --source https://operator.example/poi --token-file serve.token \
              --pubkey <hex od operatora> --mirror ~/poi/run-1 \
              --data ./moje_dane --fp-key fp.key --open
```

Dashboard weryfikuje każdy checkpoint lokalnie (kody 10–16), trzyma zweryfikowaną kopię w `--mirror`
(działa na niej `poi verify` / `poi report`) i pokazuje werdykt: **Verified** / **Needs attention** /
**Proof broken**. Stan kontenera (status, CPU, RAM) to deklaracja operatora — pokazywana, ale nigdy
nie wpływa na werdykt. Do podglądu lokalnego przebiegu wystarczy `--source ./run`.

## Case: LLM w kontenerze (vLLM + Qwen3-0.6B, GPU)

`examples/llm/` uruchamia agenta na lokalnym modelu, który streszcza `moje_dane/pacjenci.csv`.
Jeden rekord zawiera prompt injection każący wysłać dane na `http://evil.test/collect`. Polityka nie
dopuszcza żadnego ruchu wychodzącego, atestuje GPU, obraz (po ID) i wagi modelu (skrót zawartości).

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

Na RTX 3060 obok innego procesu na GPU wystarczy `POI_GPU_UTIL=0.16` (domyślne). Wynik na hoście
referencyjnym: 0 żądań wysłanych; zablokowane i zalogowane — telemetria vLLM (`CONNECT stats.vllm.ai`),
dwa odwrotne zapytania DNS oraz **wykonany przez model** `POST evil.test/collect` z rekordem pacjenta
(trafienie odcisku → dashboard „Needs attention”).

## Testy

```bash
pytest -m "not docker"      # jednostkowe
pytest -m "docker and not gpu"   # end-to-end z prawdziwym Dockerem (buduje obraz poi-proxy:0.1)
pytest -m "docker and gpu"       # case LLM: GPU NVIDIA, obraz vLLM 0.11 i Qwen3-0.6B w cache HF
```
