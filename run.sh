#!/usr/bin/env bash
set -e
python -m aegis.cli build-data --out data/alerts.jsonl --n 3000
python -m aegis.cli train --data data/alerts.jsonl
python -m aegis.cli evaluate --data data/alerts.jsonl
uvicorn aegis.server:app --host 0.0.0.0 --port "${PORT:-8080}"
