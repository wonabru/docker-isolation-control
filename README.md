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

## Testy

```bash
pytest -m "not docker"      # jednostkowe
pytest -m docker            # end-to-end z prawdziwym Dockerem (buduje obraz poi-proxy:0.1)
```
