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
} // namespace mfc_recovery
