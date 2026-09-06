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
- oczyszczone automatyzacje, skrypty, sceny, pakiety i dashboardy YAML;
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

Eksporter nigdy nie dołącza `secrets.yaml`, magazynu uwierzytelniania, danych
konfiguracyjnych integracji, baz danych, kopii zapasowych ani multimediów.
W wersji 0.2.0 może dołączyć ograniczony zestaw logów wyłącznie przy wykryciu
problemu i po zastosowaniu filtra. Filtr zawsze usuwa typowe hasła, tokeny,
klucze API, identyfikatory
webhooków i dane logowania zapisane w adresach URL.

Pełne identyfikatory encji i urządzeń, lokalne adresy IP, adresy MAC, numery VIN
oraz numery seryjne są celowo zachowywane, ponieważ pozwalają modelowi poprawnie
łączyć zależności. Ukrywanie lokalizacji jest osobną opcją i domyślnie pozostaje
wyłączone.

Automatyczny filtr nie rozpozna każdego rodzaju danych osobowych wpisanych w
nazwach i opisach. Przed wysłaniem poza dom zawsze przejrzyj gotową paczkę.

## Bezpieczeństwo

Konfiguracja Home Assistant jest zamontowana wyłącznie do odczytu. Jedynym
zapisywalnym miejscem jest `/share`, używane tylko dla wygenerowanych archiwów.
