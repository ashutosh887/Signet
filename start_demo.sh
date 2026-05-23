#!/usr/bin/env bash
# Signet — one-shot launcher for the live demo.
#
#   ./start_demo.sh           # the demo: trained anomaly, seeded, gateway, dashboard
#   ./start_demo.sh --fast    # same but skip anomaly training (~30 s faster boot)
#
# Run this in one terminal, point the judges at http://localhost:3000.
# Ctrl+C tears everything down.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VERIFIER_PORT=8000
DASHBOARD_PORT=3000
GATEWAY_PORT=8001
DB_PATH="/tmp/signet_demo.db"
VERIFIER_LOG="/tmp/signet_demo_verifier.log"
DASHBOARD_LOG="/tmp/signet_demo_dashboard.log"
GATEWAY_LOG="/tmp/signet_demo_gateway.log"

FAST=0
for arg in "$@"; do
  case "$arg" in
    --fast)    FAST=1 ;;
    -h|--help) sed -n '1,9p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
red()    { printf '\033[31m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

VERIFIER_PID=
DASHBOARD_PID=
GATEWAY_PID=

cleanup() {
  echo
  yellow "==> stopping Signet demo"
  [ -n "$VERIFIER_PID" ]  && kill "$VERIFIER_PID"  2>/dev/null || true
  [ -n "$DASHBOARD_PID" ] && kill "$DASHBOARD_PID" 2>/dev/null || true
  [ -n "$GATEWAY_PID" ]   && kill "$GATEWAY_PID"   2>/dev/null || true
  wait 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

[ -d .venv ] || { red "ERROR: .venv missing — see README §Installation"; exit 1; }
[ -d dashboard/node_modules ] || { red "ERROR: dashboard/node_modules missing — cd dashboard && pnpm install"; exit 1; }

if ! .venv/bin/python -c "import signet_verifier, multipart" >/dev/null 2>&1; then
  yellow "==> refreshing verifier dependencies (stale venv detected)"
  .venv/bin/pip install -e ./verifier >/dev/null
fi

if [ -f .env ]; then
  set -a; . ./.env; set +a
fi

VENV_PY="$ROOT/.venv/bin/python"
NEXT_BIN="$ROOT/dashboard/node_modules/.bin/next"
DYLD_LIBRARY_PATH="${DYLD_LIBRARY_PATH:-$HOME/_oqs/lib}"
LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-$HOME/_oqs/lib}"
export DYLD_LIBRARY_PATH LD_LIBRARY_PATH

bold "Signet demo launcher"
echo "  verifier  : http://localhost:$VERIFIER_PORT"
echo "  dashboard : http://localhost:$DASHBOARD_PORT"
echo "  gateway   : http://localhost:$GATEWAY_PORT  (edge device path)"
echo "  db        : $DB_PATH (fresh)"
[ $FAST -eq 1 ] && yellow "  mode      : --fast (skipping anomaly training)" \
                || echo  "  mode      : training anomaly detector on boot (~30 s)"
echo

rm -f "$DB_PATH"

yellow "==> starting verifier on :$VERIFIER_PORT"
VERIFIER_ENV=(
  SIGNET_DB_PATH="$DB_PATH"
  SIGNET_CORS_ORIGINS="http://localhost:$DASHBOARD_PORT"
)
if [ $FAST -eq 1 ]; then
  VERIFIER_ENV+=(SIGNET_SKIP_TRAIN=1)
else
  VERIFIER_ENV+=(SIGNET_TRAIN_LEGIT=80 SIGNET_TRAIN_ROGUE=30)
fi

env "${VERIFIER_ENV[@]}" "$VENV_PY" -m uvicorn signet_verifier.main:app \
    --host 127.0.0.1 --port "$VERIFIER_PORT" --log-level warning \
    > "$VERIFIER_LOG" 2>&1 &
VERIFIER_PID=$!

for i in $(seq 1 120); do
  if curl -sf "http://127.0.0.1:$VERIFIER_PORT/health" >/dev/null; then
    green "    verifier ready (pid $VERIFIER_PID) — logs: $VERIFIER_LOG"
    break
  fi
  if ! kill -0 "$VERIFIER_PID" 2>/dev/null; then
    red "    verifier process died — see $VERIFIER_LOG"
    tail -40 "$VERIFIER_LOG" || true
    exit 1
  fi
  sleep 0.5
done
if ! curl -sf "http://127.0.0.1:$VERIFIER_PORT/health" >/dev/null; then
  red "    verifier never became ready"; exit 1
fi

if [ $FAST -eq 0 ]; then
  echo "    anomaly report: $(curl -s "http://127.0.0.1:$VERIFIER_PORT/v1/anomaly/report")"
fi

yellow "==> starting edge gateway on :$GATEWAY_PORT (listens on 0.0.0.0 for the ESP32-S3 or Mac fallback)"
SIGNET_VERIFIER="http://127.0.0.1:$VERIFIER_PORT" \
  "$VENV_PY" "$ROOT/scripts/edge_gateway.py" \
  --host 0.0.0.0 --port "$GATEWAY_PORT" \
  --verifier "http://127.0.0.1:$VERIFIER_PORT" \
  > "$GATEWAY_LOG" 2>&1 &
GATEWAY_PID=$!
for i in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:$GATEWAY_PORT/health" >/dev/null; then
    green "    gateway ready (pid $GATEWAY_PID) — logs: $GATEWAY_LOG"
    break
  fi
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    red "    gateway process died — see $GATEWAY_LOG"
    tail -40 "$GATEWAY_LOG" || true
    cleanup
  fi
  sleep 0.5
done

yellow "==> starting dashboard on :$DASHBOARD_PORT"
(
  cd dashboard
  NEXT_PUBLIC_VERIFIER_HTTP="http://localhost:$VERIFIER_PORT" \
  NEXT_PUBLIC_VERIFIER_WS="ws://localhost:$VERIFIER_PORT/ws/stream" \
  NEXT_PUBLIC_FIRMWARE_PATH="$ROOT/firmware-arduino" \
    "$NEXT_BIN" dev --port "$DASHBOARD_PORT" > "$DASHBOARD_LOG" 2>&1
) &
DASHBOARD_PID=$!

for i in $(seq 1 120); do
  if grep -q "Ready in\|started server on\|Local:.*localhost:$DASHBOARD_PORT" "$DASHBOARD_LOG" 2>/dev/null; then
    green "    dashboard ready (pid $DASHBOARD_PID) — logs: $DASHBOARD_LOG"
    break
  fi
  if ! kill -0 "$DASHBOARD_PID" 2>/dev/null; then
    red "    dashboard process died — see $DASHBOARD_LOG"
    tail -40 "$DASHBOARD_LOG" || true
    cleanup
  fi
  sleep 0.5
done

yellow "==> seeding tenant + policy + envelopes (real Gemini if a key is set)"
SIGNET_VERIFIER_URL="http://127.0.0.1:$VERIFIER_PORT" \
  "$VENV_PY" "$ROOT/scripts/demo_seed.py" --verifier "http://127.0.0.1:$VERIFIER_PORT" \
  2>&1 | sed 's/^/    /'

echo
bold "================================================================="
bold " Signet is live. Open the dashboard:"
bold "================================================================="
echo
green "  http://localhost:$DASHBOARD_PORT"
echo
echo "What the judges can do, no terminal required:"
echo "  • Hit 'Fire LLM action' to plan + sign a fresh envelope via Gemini"
echo "  • Click any green envelope row → Merkle inclusion proof"
echo "  • Click 'Revoke' next to the rogue agent → next attempt rejected"
echo "  • Footer link 'Open firmware in VS Code' → ESP32-S3 firmware (PlatformIO)"
echo
yellow "Hardware path (ESP32-S3 + boot button):"
echo "  Flash firmware-arduino/ via PlatformIO. On press → gateway → envelope."
echo
yellow "Hardware-fail fallback (Mac mic, no device):"
echo "  python scripts/voice_demo.py --audio /tmp/cmd.wav --provider gemini"
echo "  python scripts/simulate_edge_device.py --triggers 3"
echo
yellow "Press Ctrl+C to stop everything."
wait
