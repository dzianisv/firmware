// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Offline oracle for a clone MIFARE Classic card that answers a WRONG-key
// authentication with a full 36-bit frame.
//
// A real card goes silent when the reader's ar does not match suc64(nt). This
// clone sometimes answers anyway. If that answer is a deterministic function of
// the bytes the reader transmitted and the key the card really holds, then one
// captured frame is a 32-bit test: for a hypothetical key K we can predict the
// answer in RAM, and the prediction equals the capture only when K is the key
// the card used. That turns "66,000 card exchanges" into "66,000 RAM tests".
//
// Nothing here touches hardware. Pure C++, no Arduino dependencies.
//
// What is NOT assumed: the cipher convention the clone uses after the wire
// arrives. The card might clock the cipher with nr then ar (standard), only with
// nr, with zeros, with the parity bits, or not at all. `Model` enumerates those
// possibilities and `feedSearch` measures which clock count reproduces a real
// capture, so the convention is selected by evidence and not by guess.
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace mfc_offline {

// One wrong-key authentication capture.
struct Sample {
    uint32_t uid = 0;     // card UID as a big-endian word (0x1F47B5D9 on the lab card)
    uint32_t nt = 0;      // plaintext tag nonce, big-endian byte order
    uint32_t ntEnc = 0;   // the same nonce encrypted under the target key: the
                          // keystream window mfc_flipper needs (unused by matches())
    uint8_t ntPar = 0;    // 3 transmitted nonce parity bits, bit0 = MSB byte (0..7)
    uint8_t wire[8] = {}; // transmitted answer: nr' in [0..3], ar' in [4..7]
    uint8_t wirePar[8] = {}; // parity bit transmitted after each wire byte
    uint8_t rx[4] = {};   // card answer as received (still encrypted)
    uint8_t rxPar[4] = {};// parity bit received after each answer byte
    // rxPar is only meaningful when the capture recorded it. A sample built from
    // a data-only capture leaves this false and the 4 parity bits are not
    // compared, instead of being compared against a zero that was never sent.
    bool hasRxParity = false;
};

// How the card is assumed to clock its cipher while receiving the 8-byte wire.
enum Model {
    ModelNrThenAr = 0,     // standard card: nr' then ar' clocked, 64 bits
    ModelNrThenZero,       // nr' clocked, then 4 zero bytes
    ModelNrOnly,           // nr' clocked, ar' ignored
    ModelNothing,          // the wire never clocks the cipher
    ModelNrThenArParity,   // 9 clocks per byte: 8 data bits + the parity bit
    ModelPlainAnswer,      // the card sends suc96(nt) unencrypted
    ModelCount
};

const char *modelName(int model);

// Predict the card's answer for hypothetical key `key` (6 bytes, MSB first).
// Writes the encrypted answer bytes and their parity bits. Returns false for an
// unknown model id.
bool predict(
    const Sample &s, const uint8_t key[6], int model, uint8_t rx[4], uint8_t rxPar[4]
);

// True when `key` predicts the observed answer bit for bit (32 data bits and,
// when the capture recorded them, the 4 parity bits).
bool matches(const Sample &s, const uint8_t key[6], int model);

// Number of the 32 answer data bits the model reproduces. 32 = full match.
// A partial score is how a near-miss convention is recognised instead of being
// written off as "wrong".
int bitScore(const Sample &s, const uint8_t key[6], int model);

// Generic alignment probe. Derives the keystream the card must have used from
// (observed rx, suc96(nt)), then reports every clock count k in [0, maxBits]
// whose keystream reproduces it, feeding the wire bitstream as it goes.
//   withParity=false: k bits of the 8 wire data bytes, LSB first
//   withParity=true : 9 bits per byte, the wire parity bit after each byte
// Returns the number of matches written to outBits (0 = no convention fits).
int feedSearch(
    const Sample &s, const uint8_t key[6], bool withParity, int maxBits, int *outBits, int maxOut
);

// Same, but the cipher is clocked with zero input for k bits: the model where
// the card ignores what it received but still counts the bits.
int zeroFeedSearch(
    const Sample &s, const uint8_t key[6], int maxBits, int *outBits, int maxOut
);

// Build the 16-byte wire a reader holding `key` would transmit for nonce `nt`:
// nr = `nr`, ar = suc64(nt), encrypted with matching parity.
// wire[0..7] = data, wire[8..15] = parity bits in bit0 of each byte.
//
// This is what the recovery loop already sends for every candidate, so a probe
// frame built here has exactly the shape the card sees in a real sweep.
void buildReaderWire(
    uint32_t nt, uint32_t uid, const uint8_t key[6], uint32_t nr, uint8_t wire[16]
);

struct EnumResult {
    int candidates = 0; // keys the keystream solver offered
    int survivors = 0;  // of those, keys that also predict the captured answer
    int stored = 0;     // survivors written to the caller's array
    int solver = 0;     // mfc_flipper::Result as an int (0 = Ok)
};

// Enumerate the same ~66,000-candidate space mfc_flipper produces from
// (uid, nt, ntEnc, par) and keep every key whose predicted answer equals the
// capture. This is the whole point: no card exchange per candidate.
EnumResult enumerate(const Sample &s, int model, uint8_t out[][6], int maxOut);

} // namespace mfc_offline
