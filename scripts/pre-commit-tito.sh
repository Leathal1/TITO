#!/usr/bin/env bash
# TITO pre-commit hook
# Usage: scripts/pre-commit-tito.sh [scan|diff]
set -euo pipefail

MODE="${1:-diff}"
TITO_BIN="${TITO_BIN:-tito}"

# Check if tito is installed
if ! command -v "$TITO_BIN" &>/dev/null; then
  echo "⚠️  TITO not found. Install: go install github.com/Leathal1/TITO/cmd/tito@latest"
  exit 0  # Don't block commits if not installed
fi

case "$MODE" in
  scan)
    echo "🛡️ TITO: Running threat model scan..."
    $TITO_BIN scan --repo . --output /dev/null --fail-on critical
    EXIT=$?
    if [ $EXIT -eq 0 ]; then
      echo "✅ TITO: No critical threats"
    elif [ $EXIT -eq 1 ]; then
      echo "⚠️  TITO: Threats detected (non-critical, allowing push)"
    else
      echo "❌ TITO: Critical threats found — push blocked"
      echo "   Run 'tito scan --repo .' for full report"
      exit 1
    fi
    ;;

  diff)
    # Get the base branch
    BASE=$(git rev-parse --abbrev-ref HEAD@{upstream} 2>/dev/null || echo "main")

    echo "🔍 TITO: Checking for security regressions..."
    $TITO_BIN diff --repo . --base "$BASE" --head HEAD --format summary --fail-on critical 2>/dev/null && EXIT=0 || EXIT=$?

    if [ $EXIT -eq 0 ]; then
      echo "✅ TITO: No security regressions"
    elif [ $EXIT -eq 1 ]; then
      echo "⚠️  TITO: New threats detected (review recommended)"
    else
      echo "❌ TITO: Critical security regression — commit blocked"
      echo "   Run 'tito diff --repo . --base $BASE --head HEAD' for details"
      exit 1
    fi
    ;;

  *)
    echo "Usage: $0 [scan|diff]"
    exit 1
    ;;
esac
