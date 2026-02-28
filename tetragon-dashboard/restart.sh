#!/bin/bash
# Restart the Tetragon dashboard server.
# Safe to run any time — always clears kill switch policies first.
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Stopping any existing dashboard server..."
pkill -f "node server.mjs" 2>/dev/null || true
sleep 1

echo "Clearing kill switch policies..."
/usr/local/bin/tetra tp delete oc-ks-exec 2>/dev/null | head -1 || true
/usr/local/bin/tetra tp delete oc-ks-net  2>/dev/null | head -1 || true

echo "Applying Tetragon policies..."
"$DIR/apply-policies.sh" || true

echo "Starting dashboard server..."
cd "$DIR"
node server.mjs &
sleep 2

echo "Kill switch status:"
curl -s http://127.0.0.1:18790/api/killswitches
echo ""
echo "Dashboard ready → http://127.0.0.1:18790"
