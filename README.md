# poi — Proof of Isolation

Kryptograficzny dowód (przy modelu zagrożeń: niezaufany workload, zaufany host), że dane w kontenerze
Docker nie opuściły go inaczej niż przez dozwolony, w pełni zalogowany i zgodny ze schematem kanał.
Specyfikacja: `docs/superpowers/specs/2026-10-13-proof-of-isolation-design.md`.

## Instalacja

```bash
uv venv --python 3.12 && uv pip install -e '.[dev]'
```

## Użycie

```bash
poi keygen signing.key                                   # klucz Ed25519 operatora
poi fingerprint --data ./moje_dane --fp-key fp.key --out fp.bin   # opcjonalnie: odciski danych
poi run --policy policy.yaml --key signing.key --run-dir run \
        --fingerprints fp.bin --fp-key fp.key --mount ./moje_dane:/data  IMAGE CMD...
poi verify run --live                                    # kod 0 = OK, 10–17 = rodzaj błędu
poi report run --data ./moje_dane --fp-key fp.key        # raport dla właściciela danych
poi clean run                                            # usuwa zatrzymany workload i sieć
```

Workload musi korzystać z `HTTP(S)_PROXY` i ufać CA z `SSL_CERT_FILE` (ustawiane automatycznie).

## Testy

```bash
pytest -m "not docker"      # jednostkowe
pytest -m docker            # end-to-end z prawdziwym Dockerem (buduje obraz poi-proxy:0.1)
```
