#!/bin/sh
# Build and run the MIFARE Classic host tests. These cover the pure crypto and
# PRNG logic only; the ST25R3916 driver needs hardware.
set -e
cd "$(dirname "$0")/.."
SRC=src/modules/rfid
OUT=${TMPDIR:-/tmp}

g++ -std=c++17 -O2 -Wall -I"$SRC" \
    tests/test_mfc_nested_flow.cpp \
    "$SRC/crypto1.cpp" \
    "$SRC/mfc_nonce.cpp" \
    "$SRC/mfc_recovery.cpp" \
    "$SRC/mfc_nested.cpp" \
    -o "$OUT/test_mfc_nested_flow"
"$OUT/test_mfc_nested_flow"

g++ -std=c++17 -O2 -Wall -I"$SRC" \
    tests/test_mfc_static_nonce.cpp \
    "$SRC/crypto1.cpp" \
    "$SRC/mfc_recovery.cpp" \
    -o "$OUT/test_mfc_static_nonce"
"$OUT/test_mfc_static_nonce"

# Low-memory solver (mfc_flipper): Flipper mfkey's memory architecture on the
# proven single-sample math. -DMFC_FLIPPER_TESTING makes the solver allocate its
# scratch through the test's counting allocator, so peak memory is measured.
g++ -std=c++17 -O2 -Wall -pthread -DMFC_FLIPPER_TESTING -I"$SRC" \
    tests/test_mfc_flipper.cpp \
    "$SRC/crypto1.cpp" \
    "$SRC/mfc_flipper.cpp" \
    "$SRC/mfc_recovery.cpp" \
    -o "$OUT/test_mfc_flipper"
"$OUT/test_mfc_flipper"

# Offline oracle (mfc_offline): one captured wrong-key frame must identify the
# key in RAM, with no card exchange per candidate.
g++ -std=c++17 -O2 -Wall -pthread -I"$SRC" \
    tests/test_mfc_offline.cpp \
    "$SRC/crypto1.cpp" \
    "$SRC/mfc_flipper.cpp" \
    "$SRC/mfc_offline.cpp" \
    "$SRC/mfc_recovery.cpp" \
    -o "$OUT/test_mfc_offline"
"$OUT/test_mfc_offline"
