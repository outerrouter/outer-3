#!/usr/bin/env bash
# Run the Agent Control Assistant.
set -u
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "Creating virtualenv…"
  python3 -m venv .venv
fi

echo "Installing dependencies…"
.venv/bin/pip install --quiet -r requirements.txt

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

echo ""
echo "  Agent Control Assistant"
echo "  Open:  http://localhost:${PORT}"
echo "  Lock:  password (default: shift&&67)"
echo ""

exec .venv/bin/uvicorn app.main:app --host "$HOST" --port "$PORT"
