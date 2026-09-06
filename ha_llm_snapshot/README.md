# HA LLM Snapshot Exporter

Tworzy bezpieczny, przenośny snapshot Home Assistant do analizy przez zewnętrzny
model LLM.

Otwórz panel dodatku, wybierz **Utwórz snapshot**, a następnie pobierz ZIP.
Konfiguracja Home Assistant jest zamontowana wyłącznie do odczytu.

Wersja 0.3.0 pobiera wszystkie pulpity Lovelace, także zapisane przez edytor
graficzny. Opcjonalnie może również dołączyć przefiltrowane pliki JSON z
`.storage`; tę funkcję trzeba włączyć w konfiguracji dodatku.
