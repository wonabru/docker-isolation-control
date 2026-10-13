# poi dashboard — specyfikacja projektu

Data: 2026-10-13
Status: zaakceptowany projekt, przed planem implementacji
Zależy od: `2026-10-13-proof-of-isolation-design.md` (framework `poi`, gałąź `feat/poi-v1`)

## 1. Cel

Właściciel danych — **inna osoba niż operator, na innej maszynie** — widzi na bieżąco w przeglądarce,
co dzieje się z przebiegiem `poi run` u operatora, i może sprawdzić każdy szczegół. Każdy werdykt
dashboardu wynika z **lokalnej weryfikacji kryptograficznej** po stronie właściciela, nigdy z deklaracji
serwera operatora.

## 2. Decyzje

| Obszar | Decyzja |
|---|---|
| Użytkownik | Właściciel danych zdalnie (wariant B); ten sam kod obsługuje też katalog lokalny |
| Zakres danych | Pełny: checkpointy, delty, całe evidence, `policy.yaml` |
| Stan Dockera na żywo | Status, CPU, RAM, czas działania jako **deklaracje operatora (niezweryfikowane)**; **bez logów** |
| Transport | `poi serve` po stronie operatora: HTTP tylko do odczytu, token Bearer; TLS przez reverse proxy operatora (Caddy/nginx) |
| Kotwica zaufania | Klucz publiczny operatora przekazany inną drogą, podawany jako `--pubkey`; API go nie udostępnia |
| Technologia UI | Lokalny serwer w bibliotece standardowej Pythona + jedna strona HTML/JS/CSS bez kroku budowania |
| Język UI | Angielski |
| Układ | Strona główna: werdykt + kafelki + oś czasu + live feed + deklaracje operatora; inspektor zdarzeń i checkpointów jako panel boczny |
| Przechowywanie | Lokalne lustro przebiegu + przyrostowa weryfikacja (podejście 1) |
| Alarmy | 🟢 VERIFIED / 🟠 ATTENTION / 🔴 PROOF BROKEN; zablokowana próba z trafieniem odcisku → 🟠 do potwierdzenia |

## 3. Architektura

```
OPERATOR                                         WŁAŚCICIEL DANYCH
┌────────────────────────────┐   HTTPS + token  ┌───────────────────────────────────┐
│ poi run  → run/            │  (Caddy/nginx)   │ poi dashboard                     │
│ poi serve run/ :8765 ──────┼─────────────────►│  ├ Source (HttpSource|LocalSource) │
│  GET /v1/checkpoints       │                  │  ├ Mirror (lokalna kopia, atomowo) │
│  GET /v1/delta/{seq}       │                  │  ├ ChainVerifier (kody 10–16)      │
│  GET /v1/evidence/{digest} │                  │  ├ FingerprintSet (klucz lokalny)  │
│  GET /v1/policy            │                  │  ├ assess() → 🟢🟠🔴                │
│  GET /v1/runtime           │                  │  └ HTTP 127.0.0.1 + SSE → przeglądarka
└────────────────────────────┘                  └───────────────────────────────────┘
```

### Moduły

| Moduł | Odpowiedzialność |
|---|---|
| `poi.verify` (refaktor) | `ChainVerifier.feed(cp, delta_raw, get_evidence)`; `verify_chain`/`verify_policy` jako nakładki |
| `poi.serve` | Serwer `poi serve` (API operatora), long-polling, token |
| `poi.runtime_info` | Deklaracje operatora z `docker inspect` / `docker stats` |
| `poi.source` | Interfejs `Source`; `HttpSource`, `LocalSource` |
| `poi.mirror` | Synchronizacja źródło → lustro, pobieranie brakującego evidence, wywołanie weryfikatora |
| `poi.assess` | Czysta funkcja `assess(state, now) -> Verdict(level, reasons)` |
| `poi.dashboard` | Stan dashboardu (zdarzenia, trafienia, potwierdzenia), lokalny serwer API + SSE |
| `poi/dashboard_static/` | `index.html`, `app.js`, `app.css` |

## 4. API operatora: `poi serve`

`poi serve RUN_DIR --listen 127.0.0.1:8765 --token-file F` (`--new-token` generuje token do pliku `0600`).
Domyślnie tylko `127.0.0.1`. Każde żądanie wymaga `Authorization: Bearer <token>` (porównanie
`hmac.compare_digest`), inaczej 401.

| Endpoint | Odpowiedź |
|---|---|
| `GET /v1/checkpoints?from=N&wait=S` | JSON lista surowych checkpointów `seq ≥ N`; przy pustym wyniku czeka do `min(S, 30)` s na nowy |
| `GET /v1/delta/{seq}` | surowe bajty `delta/NNNNNN.jsonl`; `seq` — liczba całkowita ≥ 0, inaczej 400 |
| `GET /v1/evidence/{digest}` | surowe bajty; `digest` musi pasować do `^[0-9a-f]{64}$`, inaczej 400 |
| `GET /v1/policy` | surowy `policy.yaml` |
| `GET /v1/runtime` | `{"status","started_at","cpu_percent","mem_bytes","observed_at"}` — deklaracja operatora |

Serwer zwraca wyłącznie bajty z dysku (pliki ledgera są zapisywane atomowo), niczego nie przetwarza ani
nie podpisuje. Nie ma endpointów zapisu, listowania katalogów, logów ani klucza publicznego.

## 5. Weryfikacja przyrostowa i lustro

### 5.1 `ChainVerifier`

`ChainVerifier(pubkey_hex, policy | None)` przechowuje stan obecnie lokalny dla `verify_chain`
(akumulatory, multizbiór stanu, `next_seq`, dozwolone i widziane `seq`, poprzedni checkpoint, bieżący
klucz po rotacji) oraz `VerifyResult`. `feed(cp, delta_raw, get_evidence)` wykonuje dla jednego
checkpointu wszystkie dotychczasowe kontrole: 10–13 z `verify_chain` oraz — gdy podano politykę —
14–16 z `verify_policy` dla zdarzeń i konfiguracji tego checkpointu; zwraca nowe `Event`. `verify_chain` i
`verify_policy` zachowują sygnatury i zachowanie (wszystkie istniejące testy przechodzą bez zmian).
`poi.verify` nadal importuje tylko `canonical`, `lthash`, `evidence`, `policy`.

### 5.2 Lustro

Katalog o układzie przebiegu (`ledger/`, `delta/`, `evidence/`, `policy.yaml`) plus `pubkey` (z
`--pubkey`), `source.json` (URL), `acks.json` (potwierdzone `seq`). `poi verify` i `poi report` działają na
lustrze bez zmian.

Pętla synchronizacji (wątek):
1. Przy starcie: odtworzenie weryfikacji z plików lustra; pobranie `policy.yaml` (jeśli lustro go nie ma).
2. `GET /v1/checkpoints?from=<next>&wait=25`.
3. Dla każdego checkpointu: delta → wyznaczenie skrótów evidence (egress: nagłówki i body; ingress:
   nagłówki i body; config) → pobranie brakujących → zapis atomowy → `feed`.
4. `GET /v1/runtime` co `tick_seconds`.

Błąd weryfikacji: pliki zostają w lustrze (dowód nieprawidłowości), werdykt 🔴 trwale, synchronizacja
łańcucha zatrzymana. Błąd sieci: ponowienia z wykładniczym odstępem (max 30 s).

### 5.3 Odciski

`FingerprintSet` liczony przy starcie z `--data` i `--fp-key` (k, w z polityki). Każde body egress
(dozwolone i zablokowane) jest skanowane po weryfikacji checkpointu, który je zawiera.

## 6. Alarmy

`assess(state, now) -> Verdict(level, reasons: list[str])`, czysta funkcja.

| Poziom | Warunki |
|---|---|
| 🔴 `PROOF BROKEN` | `VerifyError` (10–16); trafienie odcisku w ruchu **dozwolonym** |
| 🟠 `ATTENTION` | niepotwierdzona zablokowana próba z trafieniem odcisku; brak nowego checkpointu > 3 × `tick_seconds` od **lokalnego** odbioru ostatniego (o ile operator nie deklaruje `exited`); źródło nieosiągalne > 3 × `tick_seconds`; nieograniczona pojemność kanału w polityce |
| 🟢 `VERIFIED` | brak powyższych |

Gdy operator deklaruje `exited`, zamiast alarmu o braku checkpointu UI pokazuje szary napis
`Run finished (operator-declared)`. Zablokowane żądania bez trafienia odcisku są tylko wpisem w feedzie.
Zmiana poziomu na 🟠/🔴 wywołuje powiadomienie przeglądarki (Notification API) i zmianę tytułu karty.

## 7. Dashboard lokalny

`poi dashboard --source URL|DIR [--token-file F] --pubkey HEX --mirror DIR [--data DIR --fp-key K]
[--listen 127.0.0.1:8780]`. Serwer tylko na `127.0.0.1`; przy starcie drukuje URL z losowym kluczem sesji
(`?key=…`, następnie cookie `HttpOnly; SameSite=Strict`); żądania bez klucza → 403.

| Endpoint | Odpowiedź |
|---|---|
| `GET /` | `index.html` |
| `GET /api/summary` | werdykt + powody; kafelki (ostatni checkpoint: wiek, sent/blocked, trafienia w allowed/blocked, pojemność kanału); oś czasu (ostatnie 200 checkpointów: seq, t, liczby zmian); deklaracje operatora |
| `GET /api/events?before=&limit=&kind=all\|allowed\|blocked\|dns` | zdarzenia, najnowsze najpierw |
| `GET /api/event/{seq}` | pola elementu, werdykt, powód, nagłówki, body (tekst lub hex, max 64 KB, flaga `truncated`), wynik ponownej walidacji schematu, źródła trafień odcisków, odpowiedź ingress, checkpoint zawierający zdarzenie |
| `GET /api/checkpoint/{seq}` | pliki dodane / usunięte / zmienione (ścieżki), zmiana konfiguracji (poprzedni i nowy JSON), skróty akumulatorów, `prev`, status podpisu |
| `POST /api/ack/{seq}` | potwierdzenie 🟠 dla zdarzenia `seq` (zapis do `acks.json`) |
| `GET /api/stream` | SSE, zdarzenie `update` przy nowym checkpoincie, zmianie werdyktu lub deklaracji |

Strona (angielski; jasny i ciemny motyw): pasek werdyktu z powodami; kafelki; oś czasu checkpointów
(kolor = stan, klik → inspektor); live feed z filtrami i znacznikiem ⚠ przy trafieniu odcisku (klik →
inspektor); szary panel `Operator-declared (unverified)`; inspektor jako wysuwany panel z prawej.

Bezpieczeństwo UI: dane z evidence renderowane wyłącznie przez `textContent`; nagłówek
`Content-Security-Policy: default-src 'self'`; brak zasobów z zewnątrz.

## 8. Obsługa błędów

| Sytuacja | Zachowanie |
|---|---|
| 401 od źródła | błąd przy starcie, czytelny komunikat, kod wyjścia ≠ 0 |
| Źródło nieosiągalne | ponowienia; po 3 × `tick_seconds` 🟠 `Source unreachable since …` |
| 404 evidence / uszkodzony JSON checkpointu | 3 ponowienia, potem 🔴 (16 / 11) |
| `policy.yaml` źródła ≠ skrót w checkpointach | 🔴 (15) |
| Restart dashboardu | odtworzenie z lustra, dalej od następnego `seq` |
| Zmanipulowane dane w lustrze (lokalnie) | wykryte przy odtwarzaniu → 🔴 |

## 9. Testy

- `serve`: 401 bez/ze złym tokenem; 400 dla złego `seq`/`digest`; long-poll zwraca po zapisie nowego
  checkpointu z innego wątku; `/v1/runtime` z fałszywym klientem Dockera.
- `ChainVerifier`: `feed` po kolei ≡ `verify_chain` + `verify_policy`; wszystkie istniejące testy bez zmian.
- `mirror`: `LocalSource` i `HttpSource` (prawdziwy `poi serve` w wątku) na przebiegu z `make_engine`;
  źródło podające zmanipulowany checkpoint → 🔴 i pliki zachowane; restart z lustra.
- `assess`: tabela przypadków dla każdego warunku ze sztucznym zegarem.
- API dashboardu: kształt odpowiedzi; 403 bez klucza; statyczny JS nie używa `innerHTML` z danymi.
- E2E (`docker`): workload + `poi serve` + dashboard → 🟢; próba wycieku z danymi użytkownika → 🟠;
  `ack` → 🟢.
- Ręcznie: przegląd strony w przeglądarce i zrzut ekranu przed zakończeniem.

## 10. Poza zakresem

Logi workloadu; wielu właścicieli w jednym przebiegu (jeden przebieg = jeden właściciel); weryfikacja w
przeglądarce (JS); TLS wbudowany w `poi serve` (A2: certyfikat self-signed z przypiętym odciskiem);
publikacja do Rekor.

## 11. Korekty po prototypie (2026-10-13)

Mają pierwszeństwo przed wcześniejszymi sekcjami.

1. `ChainVerifier.feed` jest atomowy: przy `VerifyError` stan weryfikatora się nie zmienia. Dodano
   `verify_run(run_dir, pubkey, policy)` — przyrostowy odpowiednik `verify_chain` + `verify_policy`.
2. Lustro zapisuje checkpoint i deltę **przed** weryfikacją (dowód nieprawidłowości zostaje), a evidence
   tylko wtedy, gdy skrót treści zgadza się z nazwą. Lustro odmawia pracy z katalogiem utworzonym dla
   innego klucza operatora. Checkpoint spoza kolejności od źródła → 🔴 (kod 11).
3. `Snapshot.run_finished` wynika z deklaracji operatora `status == "exited"`.
4. Strona pobiera `/api/summary` od razu po załadowaniu, a SSE wysyła pełne podsumowanie przy każdej
   zmianie i co 2 s (świeży wiek checkpointu i wykrywanie braku checkpointów).
5. `POST /api/ack/{seq}` wymaga nagłówka `x-poi: 1` (ochrona CSRF obok `SameSite=Strict`).
6. Wysokości ogniw taśmy ustawiane przez CSSOM (`element.style`), bo CSP zabrania atrybutów `style`.
7. `HttpSource` zgłasza `AuthError` przy 401; `poi dashboard` kończy się wtedy kodem 2.
