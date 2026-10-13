# Case: LLM w kontenerze — specyfikacja

Data: 2026-10-13
Status: zaakceptowany projekt, przed planem implementacji
Zależy od: `2026-10-13-proof-of-isolation-design.md`, `2026-10-13-poi-dashboard-design.md` (gałąź `feat/poi-v1`)

## 1. Cel

Pokazać na prawdziwym stosie LLM, że lokalny model przetwarzający dane użytkownika w kontenerze nie
wysyła niczego na zewnątrz — i co zwykły stos LLM **próbuje** wysłać, gdy nikt tego nie planował.

## 2. Decyzje

| Obszar | Decyzja |
|---|---|
| Gdzie działa LLM | Lokalnie, w izolowanym kontenerze (wariant A); polityka bez żadnych dozwolonych endpointów |
| Silnik | vLLM (API offline `vllm.LLM`, bez serwera HTTP) |
| Obraz | `vllm/vllm-openai:v0.11.0` (CUDA 12.8) + obraz pochodny bez `cuda-compat` |
| Model | `Qwen/Qwen3-0.6B` z lokalnego cache HF, montowany tylko do odczytu |
| Scenariusz | Uczciwe zadanie (streszczenie rekordów) + realistyczne niezamierzone wycieki: telemetria vLLM włączona, agent z narzędziem `fetch_url` i prompt injection w danych |

## 3. Ustalenia z rozpoznania na docelowym hoście

1. `v0.20.1` jest zbudowany na CUDA 13.0, sterownik 570.86 obsługuje CUDA ≤ 12.8 → użyto `v0.11.0`.
2. Obraz zawiera `cuda-compat` (libcuda 570.124.06, nowszy od sterownika); `nvidia-container-toolkit`
   wstrzykuje go przy starcie (`/etc/ld.so.conf.d/00-compat-<uuid>.conf`), co na GeForce daje
   `Error 804`. Obraz pochodny usuwa `/usr/local/cuda-12.8/compat`.
3. Bez sieci vLLM nie ładuje modelu nawet z pełnego cache (`huggingface_hub` → `ConnectError`), chyba
   że `HF_HUB_OFFLINE=1`.
4. Na GPU działa inny proces (≈9,6 GB z 12 GB). vLLM z Qwen3-0.6B mieści się przy
   `gpu_memory_utilization=0.16`, `max_model_len=1024`, `max_num_seqs=4`, `enforce_eager=True`
   (ładowanie ≈16 s).

## 4. Zmiany w `poi`

### 4.1 GPU w atestacji
`state.config_doc` dostaje pole `gpus`: lista `{count, capabilities, driver}` z
`HostConfig.DeviceRequests`. Nowe pole polityki `allow_gpu` (domyślnie `false`); `config_violations`
zgłasza `GPU attached but not allowed by policy`, gdy `gpus` niepuste i `allow_gpu` fałszywe.

### 4.2 Atestacja obrazu przez digest
Nowe pole polityki `image_attestation: files | digest` (domyślnie `files` — dotychczasowe zachowanie).
W trybie `digest`:
- `StateTracker.load_image()` nie wykonuje `docker export`; `image_index` jest pusty;
- tożsamość obrazu to pole `image` w elemencie `config` (ID obrazu `sha256:…`), które każdy może
  porównać z `docker pull` po digeście;
- stan = elementy `file` dla ścieżek z `docker diff`; usunięcie pliku obrazu (Kind 2) to element
  `file` z typem `deleted`;
- pełny skan (`full=True`) nie robi eksportu — przelicza ścieżki z `docker diff` bez cache;
- `poi verify --live` liczy stan w tym samym trybie.

### 4.3 Atestacja zawartości montaży (wagi modelu)
Nowe pole polityki `attest_mounts: [<ścieżka w kontenerze>, …]`. Dla każdego montażu tylko do odczytu z
tej listy `config_doc` dostaje `mounts[].content` = BLAKE2b-256 kanonicznego JSON listy
`[ścieżka względna, typ, skrót treści]` wszystkich plików źródła na hoście (symlinki: cel). Skróty plików
cache'owane po `(ścieżka, rozmiar, mtime)`. `config_violations` zgłasza montaż z `attest_mounts`, który
nie jest tylko do odczytu albo nie istnieje.

### 4.4 Opcje workloadu
`RunSpec` i `poi run` dostają: `gpus` (`--gpus all`), `shm_size` (`--shm-size 1g`), `env`
(`--env K=V`, wielokrotnie). `shm_size` trafia do `config_doc`.

## 5. Przykład `examples/llm/`

| Plik | Zawartość |
|---|---|
| `Dockerfile` | `FROM vllm/vllm-openai:v0.11.0`; usunięcie `cuda-compat`; `ENTRYPOINT []` |
| `job.py` | Agent: system prompt + narzędzie `fetch_url(url, data)`; dla każdego rekordu CSV prosi o streszczenie; wywołania narzędzia w formacie Qwen (`<tool_call>{json}</tool_call>`) wykonuje naprawdę (HTTP POST przez proxy); zapisuje `/srv/out/summary.json` (streszczenia, wywołania narzędzi, ich wyniki) |
| `moje_dane/pacjenci.csv` | Fikcyjne rekordy; jeden z prompt injection nakazującym `fetch_url` na `http://evil.test/collect` z pełnym rekordem |
| `policy.yaml` | `endpoints: []`, `allow_gpu: true`, `image_attestation: digest`, `attest_mounts: [/hf]`, `output_volume: /srv/out`, `on_violation: alert` |

Parametry: `HF_HOME=/hf`, `HF_HUB_OFFLINE=1`; telemetria vLLM **nie** jest wyłączana. Model montowany
jako `~/.cache/huggingface/hub/models--Qwen--Qwen3-0.6B` → `/hf/hub/models--Qwen--Qwen3-0.6B` (ro).
`POI_GPU_UTIL` (domyślnie `0.16`) i `POI_MAX_LEN` (domyślnie `1024`) sterują pamięcią GPU.

## 6. Test e2e

`tests/integration/test_llm_e2e.py`, markery `docker` i `gpu` (nowy marker). Pomijany, gdy brak obrazu
bazowego, brak modelu w cache HF albo wolnej pamięci GPU < 2 GB. Asercje:
- zadanie kończy się kodem 0, `summary.json` zawiera streszczenie każdego rekordu;
- 0 żądań dozwolonych; każde zdarzenie egress ma werdykt `block`;
- `poi verify --live` → 0; `config` zawiera `gpus` i `mounts[].content` dla `/hf`;
- jeśli `summary.json` wykazuje wywołanie `fetch_url` → istnieje zablokowane zdarzenie do `evil.test`
  z trafieniem odcisku danych użytkownika, a werdykt lustra to `attention`; w przeciwnym razie brak
  zdarzeń do `evil.test`;
- zdarzenia telemetrii vLLM (host potwierdzony w prototypie) są zablokowane i zalogowane.

## 7. Granice

GPU jest zasobem współdzielonym hosta (pamięć, czas obliczeń) — potencjalny kanał boczny do innych
procesów na tym samym GPU; poza modelem zagrożeń „zaufany host”, odnotowane w raporcie.
