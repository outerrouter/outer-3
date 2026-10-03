#!/usr/bin/env bash
# Run the app with a simple supervisor: if uvicorn exits, restart it.
# Usage: ./run_server.sh [PORT] [HOST]
set -u
cd "$(dirname "$0")"
PORT="${1:-8000}"
HOST="${2:-0.0.0.0}"
mkdir -p data
LOG="data/server-${PORT}.log"
while true; do
  echo "[supervisor] starting uvicorn on ${HOST}:${PORT} at $(date -u +%FT%TZ)" >> "$LOG"
  .venv/bin/uvicorn app.main:app --host "$HOST" --port "$PORT" >> "$LOG" 2>&1
  code=$?
  echo "[supervisor] uvicorn exited (code=$code); restarting in 2s" >> "$LOG"
  sleep 2
done
