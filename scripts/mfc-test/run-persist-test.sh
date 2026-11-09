#!/bin/bash
# Prove MIFARE Classic key persistence on a Cardputer ADV, without a sweep.
#
# What it does:
#   session A  read the card (dictionary keys only), which writes the per-card
#              key sidecar, then print which sectors are known
#   reboot     over serial, so RAM is empty
#   session B  read again with nothing injected. Sectors that open must appear
#              as "opened by a saved key" in the serial log.
#
# Read-only with respect to the card: reads and auths only, no writes.
#
# Usage:
#   PORT=/dev/cu.usbmodem1101 scripts/mfc-test/run-persist-test.sh
#   PORT=... EXTRA_KEYS_FILE=~/keys.txt scripts/mfc-test/run-persist-test.sh
#
# EXTRA_KEYS_FILE is optional and local-only: one "Key A sector <n>: AA BB ..."
# line per previously recovered key. It is never printed and never committed.
set -u
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT" || exit 1
STATE_DIR=${STATE_DIR:-$HOME/.local/state/cardputer}
PORT=${PORT:-}
mkdir -p "$STATE_DIR"
LOG="$STATE_DIR/persist.log"
: > "$LOG"

PORT_ARGS=()
[ -n "$PORT" ] && PORT_ARGS=(--port "$PORT")

hexkey() {
  [ -n "${EXTRA_KEYS_FILE:-}" ] || return 1
  grep -hE "^Key A sector $1:" "$EXTRA_KEYS_FILE" 2>/dev/null | head -1 | sed 's/.*: //; s/ //g'
}

echo "A start $(date -u +%FT%TZ)" >>"$LOG"
ARGS=(test --rfid --require-tag --skip-read --command-timeout 1500)
ARGS+=("${PORT_ARGS[@]}")
for s in 1 5 6 7; do
  k=$(hexkey "$s") && [ -n "$k" ] && ARGS+=(--rfid-command "rfid mfcaddkey $k")
done
ARGS+=(--rfid-command "rfid read 5000" --rfid-command "rfid mfckeys show")
~/.venv/bin/python3 scripts/cardputer_device.py "${ARGS[@]}" >>"$LOG" 2>&1
echo "A end $(date -u +%FT%TZ) exit=$?" >>"$LOG"

echo "B reboot $(date -u +%FT%TZ)" >>"$LOG"
~/.venv/bin/python3 - "${PORT:-/dev/cu.usbmodem101}" <<'PY' >>"$LOG" 2>&1
import serial, sys, time
s = serial.Serial(sys.argv[1], 115200, timeout=1)
s.write(b"reboot\n")
time.sleep(2)
s.close()
print("reboot sent")
PY
sleep 25

echo "B start $(date -u +%FT%TZ)" >>"$LOG"
ARGS=(test --rfid --require-tag --skip-read --command-timeout 1500)
ARGS+=("${PORT_ARGS[@]}")
ARGS+=(--rfid-command "rfid read 5000" --rfid-command "rfid mfckeys show")
for attempt in 1 2 3; do
  ~/.venv/bin/python3 scripts/cardputer_device.py "${ARGS[@]}" >>"$LOG" 2>&1 && break
  echo "retry session B (the ST25R3916 sometimes misses the first boot-time probe)" >>"$LOG"
  sleep 5
done
echo "B end $(date -u +%FT%TZ)" >>"$LOG"

echo "=== verdict" >>"$LOG"
L=$(ls -dt "$STATE_DIR"/*-test 2>/dev/null | head -1)
grep -E "opened by a saved key|^Pages:|^Keys known" "$L/serial-transcript.log" >>"$LOG" 2>/dev/null
tail -25 "$LOG"
