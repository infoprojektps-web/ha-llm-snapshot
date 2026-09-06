#!/usr/bin/with-contenv bashio

bashio::log.info "Starting HA LLM Snapshot Exporter"
exec python3 /app/server.py

