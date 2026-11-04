// SPDX-License-Identifier: GPL-3.0-only
// mfoc-style nested key recovery: candidate plaintext filtering and solving.
// See docs/MFC_RECOVERY_LICENSE.md.
#pragma once
#include <stdint.h>
#include "mfc_recovery.h"

namespace mfc_nested {

// One nested-authentication capture against the target sector:
//   nt1 - plaintext nonce from the preceding known-key authentication
//   enc - encrypted nonce returned for the target sector
//   par - raw parity bits following the first three encrypted nonce bytes
struct Capture {
    uint32_t nt1;
    uint32_t enc;
    uint8_t par[3];
};

// True when nt is a plausible plaintext for enc given the received parity bits.
bool parity_ok(uint32_t nt, uint32_t enc, const uint8_t par[3]);

// Walk PRNG distances outward from median (0, +-2, +-4, ... up to tolerance),
// exactly the window mfoc's mf_enhanced_auth() recovery mode searches. For each
// distance the candidate plaintext of every capture is filtered by the nonce
// parity bits; the first two surviving captures are solved with
// mfc_recovery::recover(). Returns Found and writes key on success.
// attempts, when non-null, receives the number of solver calls spent.
mfc_recovery::Result solve(uint32_t uid, const Capture *captures, int count, uint32_t median,
                           uint32_t tolerance, uint8_t key[6],
                           mfc_recovery::Progress progress = nullptr, void *context = nullptr,
                           unsigned *attempts = nullptr);

} // namespace mfc_nested
