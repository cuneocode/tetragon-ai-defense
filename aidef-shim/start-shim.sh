#!/usr/bin/env bash
# Start the AI Defense shim (OpenClaw → shim → vLLM). Uses .env for config.
# Safe to run anytime — stops any existing shim on the same port first.

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "Stopping any existing shim on port 9000..."
pkill -f "node --env-file=.env index.js" 2>/dev/null || true
pkill -f "aidef-shim.*index.js" 2>/dev/null || true
fuser -k 9000/tcp 2>/dev/null || true
sleep 1

echo "Starting AI Defense shim..."
node --env-file=.env index.js &
sleep 2

if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:9000/healthz | grep -q 200; then
  echo "Shim ready → http://127.0.0.1:9000"
else
  echo "Shim may still be starting. Check: curl http://127.0.0.1:9000/healthz"
fi
