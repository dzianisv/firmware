// SPDX-License-Identifier: GPL-3.0-only
// Modified portable FlipperMfkey adaptation, 2026-10-25. See docs/MFC_RECOVERY_LICENSE.md.
#pragma once
#include <stdint.h>
#ifdef MFC_RECOVERY_TESTING
#include <stddef.h>
#endif

namespace mfc_recovery {
#ifdef MFC_RECOVERY_TESTING
// Native tests account for the real allocation and can force allocation failure.
void *test_allocate(size_t bytes);
void test_release(void *allocation);
#endif
struct Sample {
    uint32_t nt;        // Plaintext nonce, in Crypto1 word (big-endian byte) order.
    uint32_t encrypted; // Encrypted nonce, NOT the keystream (keystream = nt ^ encrypted).
};
enum class Result { Found, NotFound, Cancelled, NoMemory, InvalidInput, Overflow };
using Progress = bool (*)(unsigned completed, unsigned total, void *context);

// Pin the ~98 KiB solver scratch now so that later heap fragmentation (e.g.
// from reading accessible blocks before recovery) cannot prevent the solver
// from running. The scratch is shared by the nested and static-nonce paths
// and is freed by releaseSolverScratch().
bool reserveSolverScratch();
void releaseSolverScratch();

// Recover from independent authentications under the same unknown key and UID.
// key is six bytes, most significant byte first; unchanged unless Found.
// Null key or equal plaintext nonces => InvalidInput. All uint32_t values are valid.
// Callback total is 256; completed counts exhausted buckets (may repeat).
// Called at least every 4096 semi-states and during the final join; false cancels.
// No callback means no yielding. Scratch allocation: 98,368 bytes, freed on all exits.
// Overflow means a checked capacity was exceeded, NOT an exhaustive NotFound.
// Found verifies both samples, but two samples do not mathematically guarantee uniqueness.
Result recover(uint32_t uid, const Sample &first, const Sample &second, uint8_t key[6],
               Progress progress = nullptr, void *context = nullptr);

// Static-nonce cards repeat one nonce forever, so only a single keystream
// window is ever available and the key is underdetermined (2^16 states before
// parity). Offer every key consistent with `sample` and the three transmitted
// nonce parity bits to `sink`. sink returns true to accept a candidate, which
// stops the search. key is six bytes, most significant byte first.
using CandidateSink = bool (*)(const uint8_t key[6], void *context);
Result enumerateKeys(uint32_t uid, const Sample &sample, int parity, CandidateSink sink,
                     void *context, Progress progress = nullptr, void *progressContext = nullptr);
} // namespace mfc_recovery
