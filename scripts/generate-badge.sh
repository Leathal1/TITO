#!/usr/bin/env bash
# Generate a shields.io badge URL from TITO scan results
# Usage: scripts/generate-badge.sh [tito-results.json | threat-model.md]
set -euo pipefail

INPUT="${1:-}"
TOTAL=0
CRITICAL=0

if [ -z "$INPUT" ]; then
  echo "Usage: $0 <tito-results.json|threat-model.md>"
  exit 1
fi

if [[ "$INPUT" == *.json ]]; then
  TOTAL=$(jq '.threats | length' "$INPUT" 2>/dev/null || echo "0")
  CRITICAL=$(jq '[.threats[] | select(.severity == "critical")] | length' "$INPUT" 2>/dev/null || echo "0")
elif [[ "$INPUT" == *.md ]]; then
  TOTAL=$(grep -c "^### Threat:" "$INPUT" 2>/dev/null || echo "0")
  CRITICAL=$(grep -ci "severity.*critical" "$INPUT" 2>/dev/null || echo "0")
fi

# Determine color
if [ "$CRITICAL" -gt 0 ]; then
  COLOR="critical"
  STATUS="${TOTAL}%20threats%20(${CRITICAL}%20critical)"
elif [ "$TOTAL" -gt 10 ]; then
  COLOR="orange"
  STATUS="${TOTAL}%20threats"
elif [ "$TOTAL" -gt 0 ]; then
  COLOR="yellow"
  STATUS="${TOTAL}%20threats"
else
  COLOR="brightgreen"
  STATUS="clean"
fi

BADGE="https://img.shields.io/badge/TITO-${STATUS}-${COLOR}?style=flat-square"

echo "$BADGE"

# Also output markdown
echo ""
echo "Markdown:"
echo "[![TITO](${BADGE})](https://github.com/Leathal1/TITO)"
