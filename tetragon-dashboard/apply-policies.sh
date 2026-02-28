#!/bin/bash
# Apply Tetragon dashboard policies. Safe to run after reboot or when policies are missing.
# Loads the four main tracing policies in monitor mode (no kill switches).
# Usage: ./apply-policies.sh   or   bash apply-policies.sh

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
POLICIES_DIR="$DIR/policies"
TETRA="${TETRA:-/usr/local/bin/tetra}"
DEFAULT_MODE="${TETRAGON_POLICY_MODE:-monitor}"

# Main dashboard policies (same order as dashboard UI). Do not add oc-ks-exec / oc-ks-net here.
POLICIES=(oc-llm-api-egress oc-tool-exec oc-file-ops oc-skill-sandbox)

if [[ ! -x "$TETRA" ]]; then
  echo "Error: tetra not found at $TETRA" >&2
  exit 1
fi

echo "Tetragon policies: applying (mode=$DEFAULT_MODE)..."

loaded_json="$("$TETRA" tp list -o json 2>/dev/null)" || loaded_json=""
apply_count=0

for name in "${POLICIES[@]}"; do
  yaml="$POLICIES_DIR/$name.yaml"
  if [[ ! -f "$yaml" ]]; then
    echo "  Skip $name (no $yaml)"
    continue
  fi
  if echo "$loaded_json" | grep -q "\"name\":\"$name\"" 2>/dev/null; then
    echo "  $name already loaded"
    continue
  fi
  if "$TETRA" tp add "$yaml" -m "$DEFAULT_MODE" 2>/dev/null; then
    echo "  + $name"
    ((apply_count++)) || true
  else
    echo "  Failed to load $name" >&2
  fi
done

echo "Done. Loaded $apply_count new policies."
exit 0
