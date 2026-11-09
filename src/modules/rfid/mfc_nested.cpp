// SPDX-License-Identifier: GPL-3.0-only
// mfoc-style nested key recovery: candidate plaintext filtering and solving.
// See docs/MFC_RECOVERY_LICENSE.md.
#include "mfc_nested.h"
#include "mfc_nonce.h"
#include <string.h>

namespace mfc_nested {
namespace {

// mfc_recovery::recover() costs seconds per call on the device, so the number
// of calls, not the number of parity-filtered candidates, is the real budget.
constexpr int kMaxCandidates = 6;
constexpr unsigned kMaxSolverCalls = 8;

} // namespace

bool parity_ok(uint32_t nt, uint32_t enc, const uint8_t par[3]) {
    return mfc_nonce_parity_filter_ok(nt, enc, par) != 0;
}

mfc_recovery::Result solve(uint32_t uid, const Capture *captures, int count, uint32_t median,
                           uint32_t tolerance, uint8_t key[6], mfc_recovery::Progress progress,
                           void *context, unsigned *attempts) {
    if (attempts) *attempts = 0;
    if (!captures || count < 2 || !key) return mfc_recovery::Result::InvalidInput;

    unsigned calls = 0;

    // Walk the distance window outward from the measured median: 0, +-2, +-4
    // and so on up to the tolerance. A card whose PRNG advance is constant
    // resolves on the first distance; a card with a little jitter resolves on
    // the median of its captures. A wrong distance only costs a failed verify.
    for (uint32_t magnitude = 0; magnitude <= tolerance; magnitude += 2) {
        for (int sign = 0; sign < (magnitude == 0 ? 1 : 2); sign++) {
            const int32_t signedDistance =
                (int32_t)median + (sign == 0 ? (int32_t)magnitude : -(int32_t)magnitude);
            if (signedDistance < 0) continue;

            int picked = 0;
            uint32_t plaintext[kMaxCandidates];
            int captureIndex[kMaxCandidates];
            for (int i = 0; i < count && picked < kMaxCandidates; i++) {
                const uint32_t nt =
                    mfc_nonce_prng_successor(captures[i].nt1, (uint32_t)signedDistance);
                if (!parity_ok(nt, captures[i].enc, captures[i].par)) continue;
                plaintext[picked] = nt;
                captureIndex[picked] = i;
                picked++;
            }
            if (picked < 2) continue;

            for (int a = 0; a < picked; a++) {
                for (int b = a + 1; b < picked; b++) {
                    if (plaintext[a] == plaintext[b]) continue;
                    if (calls >= kMaxSolverCalls) return mfc_recovery::Result::NotFound;
                    if (progress && !progress(0, 256, context))
                        return mfc_recovery::Result::Cancelled;

                    mfc_recovery::Sample first{plaintext[a], captures[captureIndex[a]].enc};
                    mfc_recovery::Sample second{plaintext[b], captures[captureIndex[b]].enc};
                    uint8_t candidate[6] = {0};
                    calls++;
                    if (attempts) *attempts = calls;
                    const auto result =
                        mfc_recovery::recover(uid, first, second, candidate, progress, context);
                    if (result == mfc_recovery::Result::Found) {
                        memcpy(key, candidate, 6);
                        return result;
                    }
                    if (result == mfc_recovery::Result::Cancelled ||
                        result == mfc_recovery::Result::NoMemory ||
                        result == mfc_recovery::Result::InvalidInput) {
                        return result;
                    }
                }
            }
        }
    }
    return mfc_recovery::Result::NotFound;
}

} // namespace mfc_nested
