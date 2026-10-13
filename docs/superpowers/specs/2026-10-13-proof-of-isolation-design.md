# Proof of Isolation — specyfikacja projektu

Data: 2026-10-13
Status: zaakceptowany projekt, przed planem implementacji

## 1. Cel

Framework, który pozwala każdemu weryfikatorowi sprawdzić — z dowodem kryptograficznym przy jawnie
określonym modelu zagrożeń — że dane użytkownika przetwarzane w kontenerze Docker nie opuściły go
inaczej niż przez dozwolony, w pełni zalogowany i zgodny ze schematem kanał.

Mechanizm: homomorficzny hasz zbioru LtHash16 (rozszerzenie elementów przez BLAKE2b). Stan kontenera,
ruch wychodzący i ruch przychodzący są trzema akumulatorami; zmiany między checkpointami rozlicza się
dodawaniem i odejmowaniem haszy elementów:

```
H(stan_t1) = H(stan_t0) + Σ H(dodane) − Σ H(usunięte)
```

## 2. Model zagrożeń

- **Przeciwnik:** kod uruchomiony wewnątrz kontenera (workload).
- **Zaufane:** host, jądro, demon Docker, proxy egress, demon `poi`, klucz podpisujący.
- **Poza zakresem v1:** złośliwy operator hosta (wymaga TEE — możliwa przyszła warstwa), ucieczka
  z kontenera przez exploit jądra.

Uwaga zasadnicza: hasz stanu wykrywa *modyfikacje*, a nie *odczyty*. Wyciek = odczyt + transmisja,
dlatego dowód opiera się na dwóch filarach: (1) integralność stanu i konfiguracji (w tym izolacji
sieci), (2) kompletność i ograniczenie treści kanału wyjścia.

## 3. Wymagania (decyzje)

| Obszar | Decyzja |
|---|---|
| Sieć | Workload tylko w sieci `internal` bez bramy; jedyne wyjście przez proxy do białej listy hostów |
| TLS | Proxy terminuje TLS; workload ufa wyłącznie CA proxy |
| Ocena treści | Schemat dozwolonych żądań (twarda granica) + odciski danych użytkownika (warstwa informacyjna) |
| Publikacja | Lokalny podpisany łańcuch checkpointów; interfejs `Publisher` pod przyszły Rekor/HTTP |
| Śledzenie stanu | Okresowy skan warstwy `UpperDir` overlayfs + warstwy obrazu liczone raz |
| Język | Python (mitmproxy, hashlib, numpy, cryptography) |

## 4. Architektura

```
┌─────────────── host (zaufany) ─────────────────────────────┐
│  ┌──────────────┐  sieć internal   ┌──────────────────┐    │
│  │  workload    │ ───────────────► │  egress-proxy    │ ──►│ biała lista
│  │              │  (tylko proxy)   │  TLS + schemat   │    │
│  │              │ ── DNS ────────► │  + odciski + DNS │    │
│  └──────┬───────┘                  └────────┬─────────┘    │
│         │ UpperDir, wolumen wyjściowy       │ WAL + socket │
│         ▼                                   ▼              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ poi-daemon: LtHash(stan), LtHash(egress),           │   │
│  │ LtHash(ingress) → podpisany łańcuch checkpointów    │   │
│  │ → Publisher (LocalPublisher; później Rekor/HTTP)    │   │
│  └─────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────┘
          poi verify / poi report  ← dowolny weryfikator
```

### Moduły (pakiet `poi`)

| Moduł | Odpowiedzialność | Zależności |
|---|---|---|
| `poi.lthash` | Rozszerzenie elementu, `add`, `sub`, `digest`, serializacja wektora | hashlib, numpy |
| `poi.canonical` | Kanoniczne kodowanie elementów i JSON checkpointów | — |
| `poi.state` | Skan warstw obrazu, `UpperDir` (whiteouty, opaque dirs), wolumenu wyjściowego, elementu `config` | lthash, canonical |
| `poi.policy` | Wczytanie `policy.yaml`, walidacja schematów, obliczanie pojemności kanału | jsonschema |
| `poi.fingerprint` | Winnowing k-gramów, keyed BLAKE2b-64, dekodery (base64, hex, URL, gzip) | hashlib |
| `poi.proxy` | Addon mitmproxy + stub DNS; WAL; przekazanie zdarzeń do demona | policy, fingerprint |
| `poi.ledger` | Delty, evidence, checkpointy, łańcuch `prev`, podpis Ed25519, rotacja kluczy | lthash, canonical, cryptography |
| `poi.publish` | Interfejs `Publisher`; implementacja `LocalPublisher` | ledger |
| `poi.daemon` | Orkiestracja: uruchomienie sieci/proxy/workloadu, pętla ticków | wszystkie powyższe, docker SDK |
| `poi.verify` | Niezależny weryfikator | **tylko** lthash, canonical, cryptography, policy |
| `poi.cli` | `poi run`, `poi verify`, `poi report`, `poi keygen` | — |

## 5. Kryptografia

### 5.1 LtHash16

- Parametry: n = 1024 współrzędnych `uint16` (2048 B), arytmetyka mod 2¹⁶ (Lewi i in., 2019).
- `expand(e)`: dla i = 0…31: `blake2b(i.to_bytes(4,'big') ‖ e, digest_size=64, person=b"poi-lthash-v1")`,
  konkatenacja 32 bloków = 2048 B, interpretowane jako 1024 × uint16 little-endian.
- `H(S) = Σ_{e∈S} expand(e) mod 2¹⁶` (multizbiór).
- `digest(v) = blake2b(v_bytes, digest_size=32, person=b"poi-digest-v1")`.

### 5.2 Kodowanie elementów (kanoniczne, z tagiem domeny)

Pola łączone bajtem `\0`; liczby dziesiętnie ASCII; skróty jako hex BLAKE2b-256.

| Domena | Element |
|---|---|
| `file` | `file`, ścieżka, typ, tryb (oktalnie), uid, gid, skrót treści (plik) / cel (symlink) / pusty (pliki specjalne) |
| `config` | `config`, skrót kanonicznego JSON: sieci, mounty (z trybem ro/rw), capabilities, user, privileged, digest obrazu, ustawienia DNS |
| `egress` | `egress`, seq, czas (RFC 3339 UTC), metoda, host, ścieżka+query, skrót nagłówków, skrót body, werdykt (`allow`/`block`), powód |
| `ingress` | `ingress`, seq (powiązany z egress), status, skrót nagłówków, skrót body |
| `dns` (w akumulatorze egress) | `dns`, seq, czas, nazwa, typ, werdykt |

`seq` jest wspólnym, ściśle rosnącym licznikiem proxy dla zdarzeń `egress` i `dns`.

### 5.3 Podpisy

Ed25519 (`cryptography`). Klucz w pliku z uprawnieniami `0600`. Rotacja: checkpoint z polem
`"rotate": "<nowy klucz publiczny>"`, podpisany starym kluczem; kolejne checkpointy podpisuje nowy.

## 6. Formaty danych

Katalog roboczy przebiegu:

```
run/
  policy.yaml
  ledger/000000.json …      # checkpointy
  delta/000000.jsonl …      # delty
  evidence/<blake2b>.bin    # pełne body żądań i odpowiedzi
  proxy-wal/                # WAL proxy
  pubkey                    # klucz publiczny Ed25519
```

### 6.1 Checkpoint (`ledger/NNNNNN.json`, kanoniczny JSON: klucze posortowane, bez spacji, UTF-8)

```json
{
  "v": 1, "seq": 42, "t": "2026-10-13T18:00:05Z",
  "prev": "<digest kanonicznego JSON poprzedniego checkpointu bez pola sig | null dla genesis>",
  "container": {"id": "…", "image": "sha256:…"},
  "policy": "<BLAKE2b-256 policy.yaml>",
  "state":   {"vec": "<base64>", "digest": "…"},
  "egress":  {"vec": "<base64>", "digest": "…", "count": 1312},
  "ingress": {"vec": "<base64>", "digest": "…", "count": 1312},
  "delta": "<BLAKE2b-256 pliku delta/NNNNNN.jsonl>",
  "restart": false,
  "sig": "<Ed25519 nad kanonicznym JSON bez pola sig>"
}
```

### 6.2 Delta (`delta/NNNNNN.jsonl`)

Jeden wiersz na operację: `{"op":"add"|"sub","acc":"state"|"egress"|"ingress","element":"<base64>"}`.

### 6.3 Polityka (`policy.yaml`)

```yaml
version: 1
on_violation: pause          # pause | alert
tick_seconds: 5
output_volume: /srv/out      # jedyny dozwolony mount rw
endpoints:
  - host: api.example.com
    method: POST
    path: /v1/score
    request_schema: { ...JSON Schema... }
    max_requests_per_minute: 60
fingerprint:
  k: 32
```

Pojemność kanału obliczana ze schematu: suma `log2(|enum|)`, `log2(zakres)` dla liczb całkowitych,
`8 · maxLength` dla stringów (stringi bez `maxLength` lub z wolnym formatem → pojemność nieograniczona
i ostrzeżenie w raporcie).

## 7. Przepływ

1. **Genesis (`poi run --policy policy.yaml IMAGE`)**: utworzenie sieci `internal`, uruchomienie proxy
   (CA, stub DNS), uruchomienie workloadu z `HTTPS_PROXY`/`HTTP_PROXY`, CA proxy i `--dns` na stub;
   `H_state = H(pliki warstw obrazu z docker save) + H(config)`; checkpoint 0.
2. **Proxy**: na każde żądanie walidacja hosta i schematu, skan odcisków (surowe body + dekodery),
   zapis zdarzenia do WAL z `fsync`, dopiero potem przekazanie żądania (lub blokada). Odpowiedź →
   zdarzenie `ingress`. Zapytania DNS: odpowiedź tylko dla hostów z białej listy, każde zapytanie
   logowane.
3. **Tick (co `tick_seconds`)**: skan `UpperDir` i wolumenu wyjściowego (indeks inode/mtime/rozmiar;
   ponowne haszowanie tylko zmienionych plików), ponowny odczyt `docker inspect`, pobranie zdarzeń
   z WAL → delta → aktualizacja trzech wektorów → zapis delty, evidence, podpisanego checkpointu →
   `Publisher.publish(checkpoint)`.
4. **Weryfikacja (`poi verify run/ [--live]`)**: dla każdego checkpointu kolejno — podpis, łańcuch
   `prev`, skrót delty, `vec_{n-1} + Σadd − Σsub == vec_n` dla trzech akumulatorów, ciągłość `seq`
   i zgodność z `count`, ponowna walidacja schematu dla każdego `allow` na podstawie evidence
   (zgodność skrótu evidence z elementem), zgodność elementu `config` z polityką (sieć internal,
   brak mountów rw poza `output_volume`). `--live`: przeliczenie stanu bieżącego kontenera
   i porównanie z ostatnim checkpointem.
5. **Raport (`poi report run/ --data DIR --key KEY`)**: lokalne obliczenie odcisków danych użytkownika
   i skan całego evidence; wynik: liczba trafień, lista prób zablokowanych, górne ograniczenie
   pojemności kanału ukrytego (bity/żądanie × liczba żądań).

## 8. Obsługa błędów (fail-closed)

| Sytuacja | Zachowanie |
|---|---|
| Niepowodzenie zapisu WAL w proxy | Żądanie blokowane |
| Restart demona | Odtworzenie z WAL, pełny skan stanu, checkpoint z `"restart": true`; ciągłość `seq` zachowana |
| Zmiana `config` niezgodna z polityką | Zmiana widoczna w haszu stanu; `on_violation` (domyślnie `docker pause`) |
| Plik zmieniany podczas haszowania | Porównanie mtime/rozmiaru przed i po; do 3 prób, potem przeniesienie na następny tick |
| Pliki specjalne | Element z typem i metadanymi, bez treści |
| Duże pliki | Haszowanie strumieniowe |
| Czas checkpointu niemonotoniczny | Błąd weryfikacji |
| Błąd weryfikacji | Osobne kody wyjścia: 10 podpis, 11 łańcuch, 12 delta/suma LtHash, 13 `seq`/`count`, 14 schemat, 15 config, 16 evidence, 17 `--live`; raport wskazuje pierwszy błędny checkpoint |

## 9. Granice dowodu

**Gwarantowane** (przy założeniach z §2, bezpieczeństwie BLAKE2b i LtHash16 n=1024):

1. **Kompletność egressu**: każdy bajt opuszczający kontener przez sieć przeszedł przez proxy i jest
   w logu (izolacja sieci atestowana elementem `config`; DNS przez stub).
2. **Ograniczenie treści**: każde dozwolone żądanie spełnia schemat; pojemność kanału jest jawnie
   policzona.
3. **Niezmienność historii**: modyfikacja, usunięcie lub przestawienie wpisu jest wykrywalne
   (łańcuch + podpis; ochrona przed rozgałęzieniem historii po dodaniu zewnętrznego `Publisher`).
4. **Integralność stanu**: każda zmiana plików, wolumenu wyjściowego i konfiguracji jest rozliczona
   w deltach.

**Niegwarantowane** (raport stwierdza to wprost):

- kanały ukryte wewnątrz schematu (timing, liczba żądań, wybór wartości) — podawane jest górne
  ograniczenie, nie zero;
- zmiany stanu krótsze niż odstęp między tickami (nie są kanałem wycieku; egress jest logowany w 100%);
- ucieczka z kontenera przez exploit jądra / kompromitacja hosta;
- wykrycie danych zaszyfrowanych lub przekształconych przez odciski (odciski są informacyjne).

## 10. Testy (pytest)

- `lthash`: testy właściwości (`hypothesis`) — przemienność, `H(A∪B)=H(A)+H(B)`, `H(A)−H(A)=0`,
  niezależność od kolejności; stałe wektory testowe (golden).
- `canonical`: determinizm; separacja domen.
- `state`: sztuczny katalog overlay z whiteoutami i opaque dirs; suma delt = pełne przeliczenie.
- `ledger`/`verify`: manipulacje — zmiana 1 bajtu w checkpoincie/delcie/evidence, usunięcie
  i przestawienie checkpointu, dziura w `seq`, podmiana klucza — każda daje oczekiwany kod błędu.
- `policy`: obliczanie pojemności kanału.
- `fingerprint` / addon proxy: allow/block wg schematu; wykrycie odcisków po base64, hex, gzip,
  URL-encode; fail-closed przy niedostępnym WAL.
- Integracyjne (`@pytest.mark.docker`): workload wykonujący dozwolone wywołania oraz próby wycieku
  (host spoza listy, bezpośrednie IP, DNS, pole spoza schematu, zakodowane dane) → wszystkie
  zablokowane i zalogowane, `poi verify` przechodzi, `poi report` pokazuje próby.
- Niezależność weryfikatora: test importów `poi.verify`.

## 11. Poza zakresem v1 (możliwe rozszerzenia)

- Zewnętrzny `Publisher` (Sigstore Rekor, publiczny endpoint HTTP).
- eBPF: korelacja odczytów plików z egressem.
- Rate-limit/padding redukujące kanały ukryte.
- TEE (Intel TDX / AMD SEV-SNP) dla modelu „niezaufany host”.
