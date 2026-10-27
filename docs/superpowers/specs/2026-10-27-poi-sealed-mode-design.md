# Tryb `--sealed` — dane klienta nieodczytywalne po audycie

Data: 2026-10-27
Status: zaakceptowany projekt, przed planem implementacji
Rozszerza: `2026-10-13-proof-of-isolation-design.md`

## 1. Cel

Klient (właściciel danych) ma wiedzieć, że po zakończeniu audytu nikt nie odczyta jego danych z tego,
co zostało na hoście — z katalogu uruchomienia, kontenera, logów, kopii zapasowych ani dysku — nawet
jeśli operator nie usunął kontenera. Klucze istnieją tylko w RAM-ie w trakcie uruchomienia
(crypto-shredding); na dysku zostaje wyłącznie szyfrogram, który odszyfruje tylko klient swoim kluczem
chronionym hasłem. Wymiana kluczy jest postkwantowa (hybryda X25519 + ML-KEM-768).

Tryb jest opcjonalny: `poi run --sealed`. Bez flagi zachowanie jest identyczne jak dziś.

## 2. Model zagrożeń

- **W trakcie uruchomienia:** bez zmian — host zaufany. Operator z rootem może w tym czasie odczytać
  dane i klucze z RAM-u; tryb sealed tego nie zmienia (wymagałoby TEE, poza zakresem).
- **Po zakończeniu uruchomienia:** host, jego dyski, kopie zapasowe i katalog uruchomienia traktujemy
  jako dostępne dla przeciwnika (ciekawski operator, wyciek backupu, przejęcie hosta w przyszłości,
  komputer kwantowy w przyszłości). Przeciwnik nie zna hasła klienta ani jego pliku klucza.
- **Gwarancja:** po poprawnym zakończeniu `poi run --sealed` żadna z poniższych lokalizacji nie zawiera
  danych klienta w postaci jawnej: katalog uruchomienia, warstwa zapisywalna kontenera, logi Dockera,
  pliki na dysku hosta. Dane jawne istniały wyłącznie w tmpfs (RAM).
- **Ograniczenia wprost:** zrzut RAM-u w trakcie; swap (patrz §6.4); równość treści jest widoczna
  (szyfrowanie deterministyczne, §5.4); długości szyfrogramów zdradzają długości treści.

## 3. Decyzje

| Obszar | Decyzja |
|---|---|
| Odszyfrowanie danych wejściowych | Po stronie hosta, do tmpfs (`/dev/shm/poi-<run_id>/`), bind-mount `ro` do kontenera — workload i obraz bez zmian |
| Klucz klienta | Para hybrydowa X25519 + ML-KEM-768 (kombinator X-Wing), klucz prywatny szyfrowany kluczem z hasła (Argon2id) |
| Przekazanie klucza danych | Grant: DEK zaszyfrowany do tymczasowej pary KEM uruchomienia (tylko w RAM-ie) — forward secrecy |
| Kanał grantu | Plik `grant.bin` wrzucany przez operatora do katalogu uruchomienia; `poi run` czeka z timeoutem |
| Evidence | Szyfrowane kluczem uruchomienia EK, który jest zaszyfrowany do klucza publicznego klienta |
| Pola ledgera | Pola mogące nieść dane klienta szyfrowane w miejscu (prefiks `s:`), liczba pól bez zmian |
| Wyjście `out/` | W tmpfs w trakcie; na końcu `out.sealed` zaszyfrowane do klienta |
| Weryfikacja | Bez klucza klienta: kody 10–13, 15, 16. Kod 14 i treść tylko z kluczem klienta |
| Zależności | Brak nowych: `cryptography` ma ML-KEM, X25519, Argon2id, AES-GCM-SIV; podnieść minimalną wersję do `>=50` |

## 4. Przepływ

```
KLIENT                                         OPERATOR (host)
poi client-keygen client.key   (hasło)
poi seal --data moje_dane --to client.pub
        --out moje_dane.sealed  ───────────▶   moje_dane.sealed, client.pub
                                               poi run --sealed --client-pub client.pub
                                                   --sealed-mount moje_dane.sealed:/data ...
                                                 → generuje parę KEM uruchomienia w RAM-ie
                                                 → zapisuje run/run.pub, czeka na run/grant.bin
                               ◀───────────   run.pub (+ run_id, w run.pub)
poi grant moje_dane.sealed --run-pub run.pub
        --key client.key --out grant.bin (hasło)
                                ───────────▶   cp grant.bin run/
                                                 → odszyfrowuje paczkę do tmpfs, start workloadu
                                                 → evidence/pola szyfrowane EK
                                                 → koniec: out.sealed, usunięcie kontenera i tmpfs
poi dashboard --client-key client.key ...  (hasło) — odszyfrowanie tylko w pamięci
poi verify run --client-key client.key      — pełna weryfikacja (z kodem 14)
```

Operator bez klucza klienta: `poi verify run` — łańcuch, podpisy, konfiguracja, integralność evidence.

## 5. Kryptografia

### 5.1 KEM hybrydowy (`poi.seal.kem`)

- Klucz publiczny: `pk_M` (ML-KEM-768, 1184 B) ‖ `pk_X` (X25519, 32 B).
- Klucz prywatny: ziarno ML-KEM (64 B, `from_seed_bytes`) ‖ X25519 (32 B).
- Enkapsulacja: `(ss_M, ct_M) = ML-KEM.Encaps(pk_M)`; efemeryczne `ek_X`, `ct_X = ek_X·G`,
  `ss_X = X25519(ek_X, pk_X)`.
  `ss = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`, `XWingLabel = b"\\.//^\\"` (kombinator
  X-Wing, draft-connolly-cfrg-xwing-kem). Szyfrogram: `ct_M ‖ ct_X` (1120 B).
- Bezpieczeństwo: łamie się tylko, gdy złamane są oba składniki (klasyczny i postkwantowy).

### 5.2 Wrap klucza (`wrap(pk, key, aad)`)

`ct_kem, ss = Encaps(pk)`; `wrapped = AES-256-GCM(ss, nonce=0^12, key, aad)` — nonce zerowy jest
bezpieczny, bo `ss` jest jednorazowy. Format: `ct_kem ‖ wrapped`.

### 5.3 Plik klucza klienta (`client.key`, JSON, `0600`)

```json
{"v": 1, "kdf": "argon2id", "m_kib": 65536, "t": 3, "p": 4, "salt": "<b64 16B>",
 "nonce": "<b64 12B>", "ct": "<b64 AES-256-GCM(KEK, priv, aad=b'poi-client-key-v1')>",
 "pub": "<hex pk>"}
```

`client.pub`: hex klucza publicznego w jednej linii. Złe hasło → błąd AEAD → komunikat „złe hasło”.

### 5.4 Szyfrowanie w uruchomieniu (EK)

- `EK` — 32 losowe bajty na uruchomienie. `run/sealed.json` zawiera `wrap(client.pub, EK,
  aad=run_id)` oraz digest `client.pub` i `run.pub`.
- Podklucze: `k_ev = HKDF-SHA256(EK, info="poi-evidence")`, `k_fld = HKDF-SHA256(EK, info="poi-field")`.
- **Evidence:** `AES-256-GCM-SIV(k_ev, nonce=0^12, data, aad=b"ev")`. Deterministyczne → deduplikacja
  w magazynie adresowanym treścią działa; równe treści dają równe szyfrogramy (wyciek równości,
  akceptowany). Nazwa pliku i digest w elemencie = `b2b256(szyfrogram)`.
- **Pola:** `"s:" + base64url(AES-256-GCM-SIV(k_fld, nonce=0^12, value, aad=<nazwa pola>))`.
  Pola szyfrowane: `egress.host`, `egress.path`, `dns.name`, `file.path` i `file.content` dla plików
  z katalogu wyjściowego. Pozostałe pola (seq, czas, metoda, werdykt, powód, typ, tryb, uid/gid)
  jawne — nie niosą danych klienta.

### 5.5 Paczka danych (`*.sealed`) — strumieniowa

```
"POISEAL1" ‖ u32 len ‖ header JSON ‖ chunk_0 ‖ chunk_1 ‖ …
header = {"v":1, "kind":"data"|"out", "chunk":1048576, "prefix":"<b64 7B>",
          "dek_wrap":"<b64 wrap(client.pub, DEK, aad=b'poi-dek')>"}
chunk_i = AES-256-GCM(DEK, nonce = prefix ‖ u32 i ‖ u8 last, plaintext_i, aad=header bytes)
```

Zawartość: archiwum tar katalogu (bez właścicieli, uprawnienia zachowane). Obcięcie lub zmiana
kolejności kawałków wykrywane (flaga `last`, licznik). Digest paczki = `b2b256` całego pliku.

### 5.6 Grant (`grant.bin`)

`wrap(run.pub, DEK, aad = run_id ‖ b2b256(paczka))` — jeden grant na każdą `--sealed-mount`
(plik zawiera listę `{bundle_digest, wrap}`). Grant dla innego uruchomienia lub innej paczki →
błąd AEAD. Klucz prywatny uruchomienia nigdy nie trafia na dysk, więc grant po uruchomieniu jest
bezużyteczny. `run.pub` zawiera `run_id`; jego digest trafia do dokumentu konfiguracji (§7), więc
klient widzi w podpisanym łańcuchu, do jakiego klucza wystawił grant.

## 6. Wykonanie w trybie sealed

### 6.1 Katalog tmpfs hosta

`/dev/shm/poi-<run_id>/` (`0700`): `data/<n>/` (odszyfrowane paczki), `out/`, `secrets/ek`,
`secrets/fingerprint.key`. Proxy dostaje `secrets/` jako dodatkowy bind-mount `ro`.
W trybie sealed `fingerprint.key` i `out/` nie powstają w katalogu uruchomienia.

### 6.2 Kontener workloadu

- `read_only=True` (rootfs), `tmpfs={"/tmp": "", <--tmpfs PATH>...}`, `log_config={"type": "none"}`.
- `--sealed-mount BUNDLE:TARGET` → bind `ro` z `/dev/shm/poi-<run_id>/data/<n>`.
- Zwykłe `--mount` nadal dozwolone (np. wagi modelu — dane operatora).
- Kontener zawsze usuwany na końcu (jak `--rm`); `poi verify --live` niedostępne po zakończeniu.

### 6.3 Proxy

`WalWriter` dostaje opcjonalny `Sealer(EK)`: szyfruje treść przed `evidence.put` oraz pola elementów
przed zapisem do WAL. Decyzje polityki i skan odcisków działają na jawnym tekście w pamięci proxy.
Demon (`engine`, `ledger`) nie wymaga zmian — widzi gotowe elementy.
`StateTracker` dostaje ten sam `Sealer` dla elementów z katalogu wyjściowego.

### 6.4 Swap

Przy aktywnym swapie (`/proc/swaps` niepusty) `poi run --sealed` odmawia startu, chyba że podano
`--allow-swap`. Stan swapu (`"swap": true|false`) trafia do dokumentu konfiguracji, więc klient go widzi.

### 6.5 Zakończenie i sprzątanie

Kolejność: zatrzymanie workloadu → końcowy checkpoint → `out/` → `run/out.sealed` (DEK losowy,
wrap do `client.pub`) → usunięcie kontenera → nadpisanie zerami i usunięcie `/dev/shm/poi-<run_id>/`
→ wyzerowanie buforów kluczy w procesie (best effort; Python nie gwarantuje). Po awarii pozostałości
są tylko w RAM-ie; `poi clean run` usuwa katalog tmpfs i kontener.

## 7. Dokument konfiguracji i polityka

Dokument konfiguracji (element `config`) w trybie sealed zawiera dodatkowo:

```json
"sealed": {"client_pub": "<b2b256>", "run_pub": "<b2b256>",
           "mounts": {"/data": "<b2b256 paczki>"}, "swap": false,
           "rootfs_ro": true, "log_driver": "none", "tmpfs": ["/tmp"],
           "out_target": "/out"}
```

Nowe pole polityki `require_sealed: true` (domyślnie `false`). `config_violations` przy
`require_sealed` zgłasza (kod 15): brak sekcji `sealed`, `rootfs_ro != true`, `log_driver != "none"`,
zapisywalny mount inny niż tmpfs i niż `out_target` (katalog wyjściowy, który w trybie sealed
leży w tmpfs hosta), `swap == true`. Dzięki temu klient może w swojej polityce wymusić tryb
sealed, a weryfikator wykryje uruchomienie bez niego.

## 8. Weryfikacja, raport, dashboard

- `poi verify run` (bez klucza): 10–13, 15, 16 (integralność szyfrogramów). Egress z zaszyfrowanymi
  polami — kontrola schematu (14) pominięta z komunikatem „sealed: schemat wymaga --client-key”.
- `poi verify run --client-key client.key`: pyta o hasło, odpakowuje EK z `sealed.json`, odszyfrowuje
  pola i evidence w pamięci, wykonuje pełne 14. Błąd odszyfrowania → nowy kod **18 (E_SEALED)**.
- `poi report` i `poi dashboard` przyjmują `--client-key`; bez niego pokazują metadane i „🔒”.
  Mirror przechowuje wyłącznie szyfrogram. Hasło podawane interaktywnie (`getpass`) lub przez
  `POI_CLIENT_PASSWORD` (do testów).
- `poi unseal out.sealed --key client.key --out DIR` — odczyt wyniku przez klienta.

## 9. Nowe moduły i CLI

| Moduł | Odpowiedzialność |
|---|---|
| `poi/seal/kem.py` | Hybrydowy KEM, `wrap`/`unwrap` |
| `poi/seal/keyfile.py` | `client.key`/`client.pub`, Argon2id |
| `poi/seal/bundle.py` | Format `*.sealed`: `seal_dir`, `unseal_to` (strumieniowo) |
| `poi/seal/grant.py` | Klucz uruchomienia, `run.pub`, tworzenie i otwieranie grantu |
| `poi/seal/sealer.py` | `Sealer(EK)`: evidence i pola, `sealed.json` |

`verify.py` może importować `poi.seal.sealer` i `poi.seal.kem` (lista dozwolonych importów w nagłówku
modułu do aktualizacji).

CLI: `client-keygen`, `seal`, `grant`, `unseal`; `run` dostaje `--sealed`, `--client-pub`,
`--sealed-mount` (wielokrotne), `--tmpfs` (wielokrotne), `--allow-swap`, `--grant-timeout`
(domyślnie 600 s); `verify`, `report`, `dashboard` dostają `--client-key`.

## 10. Obsługa błędów

| Sytuacja | Zachowanie |
|---|---|
| Brak `grant.bin` przed timeoutem | Sprzątanie, wyjście z błędem, żaden kontener workloadu nie wystartował |
| Grant do innego uruchomienia/paczki | Odrzucony (AEAD), czekanie trwa dalej do timeoutu |
| Uszkodzona/obcięta paczka | Przerwanie przed startem workloadu, wyczyszczenie tmpfs |
| Swap bez `--allow-swap` | Odmowa startu |
| `--sealed-mount` bez `--sealed` / `--sealed` bez `--client-pub` | Błąd argumentów |
| Złe hasło | „złe hasło”, kod wyjścia 2 |

## 11. Testy

- **Unit:** KEM (round-trip, zmieniony `ct_M` lub `ct_X` → błąd), keyfile (złe hasło),
  bundle (round-trip, obcięcie, zamiana kawałków, pusta paczka, plik > 1 kawałka), grant (zły `run_id`,
  zła paczka), sealer (deterministyczność, prefiks `s:`, brak NUL), `config_violations` z
  `require_sealed`, verify bez i z kluczem (kod 18 przy złym EK).
- **E2E (docker):** quickstart w trybie sealed z `--allow-swap` (host testowy ma aktywny swap).
  Po zakończeniu: przeszukanie katalogu uruchomienia, `/dev/shm` i `docker ps -a` — brak rekordów
  pacjentów (szukane po wartościach z `moje_dane`), brak kontenera, brak katalogu tmpfs; `verify` bez
  klucza → 0; `verify --client-key` → 0; `report --client-key` pokazuje treść żądania; `unseal`
  odtwarza `out/`.
- **E2E wycieku:** workload próbujący `GET evil.test/<rekord>` i DNS `<rekord>.evil.test` — rekord nie
  występuje jawnie w `ledger/`, `delta/`, `proxy-wal/`, `evidence/`; z kluczem raport go pokazuje.

## 12. Poza zakresem

- Ochrona w trakcie uruchomienia przed złośliwym hostem (TEE: SEV-SNP/TDX, GPU w trybie CC).
- Przesyłanie grantu przez `poi serve` (endpoint zapisywalny) — możliwe później.
- Ukrywanie długości treści (padding).
- Szyfrowanie wag modelu i innych danych operatora.
