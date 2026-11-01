// SPDX-License-Identifier: GPL-3.0-only
// Port of the public mfcuk/crapto1 darkside common-prefix attack, 2026-10-26.
#pragma once
#include <stdint.h>

namespace mfc_darkside {

// Recover candidate 48-bit keys from one darkside sample.
//
// prefix  : common 29-bit Nr prefix, low 3 bits zero.
// arEnc   : spoofed encrypted Ar sent to the card.
// ks[8]   : keystream nibbles recovered as (encrypted NAK ^ 0x5).
// par[8][8]: encrypted parity bits sent for each probe; columns 3..7 are used.
// uid, nt : UID and plaintext tag nonce, for the Crypto1 rollback.
// keys    : caller-owned output array.
// Returns the number of candidates, 0 if none, or -1 on bad input/overflow.
int recoverKeys(uint32_t prefix, uint32_t arEnc, const uint8_t ks[8],
                const uint8_t par[8][8], uint32_t uid, uint32_t nt,
                uint64_t *keys, int maxKeys);

// Exposed for diagnostics and tests. Returns the number of 21-bit candidates,
// or -1 when the fixed candidate buffer is too small.
int prefixCandidates(const uint8_t ks[8], int isOdd, uint32_t *out, int capacity);

} // namespace mfc_darkside
