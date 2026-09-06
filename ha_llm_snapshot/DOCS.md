# HA LLM Snapshot Exporter

Dodatek tworzy paczkę analityczną, którą można ręcznie wysłać do zewnętrznego
modelu LLM.

## Użycie

1. Uruchom dodatek i otwórz jego panel.
2. Wybierz **Utwórz snapshot**.
3. Po zakończeniu wybierz **Pobierz ZIP**.

Archiwa są również dostępne w `/share/ha-llm-snapshots/`.

## Zawartość

- wszystkie wpisy rejestru encji, również wyłączone i ukryte;
- encje istniejące tylko w bieżącym stanie oraz przefiltrowane stany;
- urządzenia, obszary, piętra, etykiety i bezpieczne podsumowania integracji;
- dostępne akcje/usługi Home Assistant;
- oczyszczone automatyzacje, skrypty, sceny i pakiety;
- wszystkie pulpity Lovelace pobrane przez API, również utworzone w edytorze
  graficznym i zapisane w pamięci Home Assistanta, wraz z zasobami Lovelace;
- opcjonalnie: przefiltrowane pliki JSON z katalogu `.storage`;
- indeks odwołań do encji i usług;
- raport zdrowia z priorytetami, diagnostyką dostępności oraz potencjalnie
  brakującymi odwołaniami;
- przy wykryciu problemu: przefiltrowane logi systemowe oraz diagnostyka
  powiązanych integracji i urządzeń;
- manifest i instrukcja analizy dla odbierającego modelu.

Rozszerzona diagnostyka jest domyślnie włączona. Jeżeli pojawi się niedostępna
encja albo integracja w stanie błędu, eksporter próbuje zebrać dodatkowe dane
tylko dla najbardziej istotnych wpisów. Brak obsługi któregoś punktu API w
danej wersji Home Assistant zostanie zapisany jako informacja w paczce i nie
przerwie tworzenia ZIP.

## Prywatność

Eksporter nigdy nie dołącza `secrets.yaml`, baz danych, kopii zapasowych ani
multimediów. Od wersji 0.3.0 katalog `.storage` można dołączyć osobną opcją,
która jest domyślnie wyłączona. Każdy plik musi być poprawnym JSON-em i jest
rekurencyjnie filtrowany przed zapisaniem; surowe pliki `.storage` nie są
kopiowane. Filtr zawsze usuwa typowe hasła, tokeny, PIN-y, klucze API,
identyfikatory webhooków i dane logowania zapisane w adresach URL.

Przed utworzeniem paczki do pełnej analizy otwórz kartę **Konfiguracja** dodatku,
włącz **Dołącz przefiltrowany katalog .storage**, zapisz ustawienia i uruchom
dodatek ponownie.

Pełne identyfikatory encji i urządzeń, lokalne adresy IP, adresy MAC, numery VIN
oraz numery seryjne są celowo zachowywane, ponieważ pozwalają modelowi poprawnie
łączyć zależności. Ukrywanie lokalizacji jest osobną opcją i domyślnie pozostaje
wyłączone.

Automatyczny filtr nie rozpozna każdego rodzaju danych osobowych wpisanych w
nazwach i opisach. Przed wysłaniem poza dom zawsze przejrzyj gotową paczkę.

## Bezpieczeństwo

Konfiguracja Home Assistant jest zamontowana wyłącznie do odczytu. Jedynym
zapisywalnym miejscem jest `/share`, używane tylko dla wygenerowanych archiwów.
