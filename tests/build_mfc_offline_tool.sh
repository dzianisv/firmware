#!/bin/sh
# Build the host tool that calibrates and runs the MIFARE Classic offline oracle.
# No hardware, no Arduino dependencies.
set -e
cd "$(dirname "$0")/.."
SRC=src/modules/rfid
OUT=${TMPDIR:-/tmp}/mfc_offline_tool

g++ -std=c++17 -O2 -Wall -I"$SRC" \
    tests/mfc_offline_tool.cpp \
    "$SRC/crypto1.cpp" \
    "$SRC/mfc_flipper.cpp" \
    "$SRC/mfc_offline.cpp" \
    -o "$OUT"
echo "built $OUT"
