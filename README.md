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

## Testy

```bash
pytest -m "not docker"      # jednostkowe
pytest -m docker            # end-to-end z prawdziwym Dockerem (buduje obraz poi-proxy:0.1)
```
