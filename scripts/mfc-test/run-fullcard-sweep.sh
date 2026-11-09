#!/bin/bash
# Sweep every locked sector of one MIFARE Classic card and then read it.
#
# Cost is the point: one sector is ~65k candidates at the measured 17/s, i.e.
# 60-80 minutes on an I2C ST25R3916. Eight sectors is most of a night. Keys are
# written to the per-card sidecar the moment each sector verifies, so a dropped
# USB link costs only the sector in flight.
#
# Read-only with respect to the card: authentication and reads only.
#
# Usage:
#   PORT=/dev/cu.usbmodem1101 SECTORS="8 9 10" scripts/mfc-test/run-fullcard-sweep.sh
#   PORT=... SECTORS="8" LONG=1 ...        # keep going even past a failed sector
#
# Optional KNOWN_KEYS_FILE: local "Key A sector <n>: AA BB ..." lines for keys
# recovered in an earlier boot, so the sweep does not repeat them.
set -u
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT" || exit 1
STATE_DIR=${STATE_DIR:-$HOME/.local/state/cardputer}
PORT=${PORT:-}
SECTORS=${SECTORS:-"6 7 8 9 10 11 12 13"}
TIMEOUT=${TIMEOUT:-10800}
mkdir -p "$STATE_DIR"
LOG="$STATE_DIR/fullcard.log"
: >"$LOG"

PORT_ARGS=()
[ -n "$PORT" ] && PORT_ARGS=(--port "$PORT")

hexkey() {
  [ -n "${KNOWN_KEYS_FILE:-}" ] || return 1
  grep -hE "^Key A sector $1:" "$KNOWN_KEYS_FILE" 2>/dev/null | head -1 | sed 's/.*: //; s/ //g'
}

ARGS=(test --rfid --require-tag --skip-read --command-timeout "$TIMEOUT")
ARGS+=("${PORT_ARGS[@]}")
for s in 1 5 6 7; do
  k=$(hexkey "$s") && [ -n "$k" ] && ARGS+=(--rfid-command "rfid mfcaddkey $k")
done
for s in $SECTORS; do
  ARGS+=(--rfid-command "rfid recover 5000 $s")
done
ARGS+=(--rfid-command "rfid read 5000" --rfid-command "rfid mfckeys show")

echo "start $(date -u +%FT%TZ) sectors:[$SECTORS]" >>"$LOG"

# The ST25R3916 sometimes misses the boot-time I2C probe on the first boot after
# a flash. That must not kill a multi-hour run in 17 seconds, so retry while
# nothing has actually run yet.
for attempt in 1 2 3; do
  ~/.venv/bin/python3 scripts/cardputer_device.py "${ARGS[@]}" >>"$LOG" 2>&1
  code=$?
  if [ "$code" -eq 0 ] || grep -q "serial: rfid recover" "$LOG"; then break; fi
  echo "attempt $attempt exited $code before any recovery; retrying in 20 s" >>"$LOG"
  sleep 20
done
echo "exit=$code end $(date -u +%FT%TZ)" >>"$LOG"
grep -E "^(PASS|FAIL): serial|static ->|New keys|^Pages:" "$LOG" | tail -30
