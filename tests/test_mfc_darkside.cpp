// Offline test for the darkside common-prefix solver.
// Generates the 8 encrypted 0x5 NAKs and parity bits a weak-PRNG card would
// return, then requires the solver to recover the known key.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/modules/rfid/crypto1.h"
#include "../src/modules/rfid/mfc_darkside.h"

namespace {

uint8_t oddparity(uint8_t b) {
    b ^= b >> 4;
    b ^= b >> 2;
    b ^= b >> 1;
    return (uint8_t)((b & 1u) ^ 1u);
}

struct Sample {
    uint8_t ks[8];
    uint8_t par[8][8];
};

bool makeSample(uint64_t key, uint32_t uid, uint32_t nt, uint32_t prefix, uint32_t arEnc,
                Sample *out) {
    if (!out) return false;

    for (uint32_t c = 0; c < 8; c++) {
        const uint32_t nrPlain = prefix | (c << 5);
        const uint8_t nr[4] = {(uint8_t)(nrPlain >> 24), (uint8_t)(nrPlain >> 16),
                               (uint8_t)(nrPlain >> 8), (uint8_t)nrPlain};
        const uint8_t ar[4] = {(uint8_t)(arEnc >> 24), (uint8_t)(arEnc >> 16),
                               (uint8_t)(arEnc >> 8), (uint8_t)arEnc};

        Crypto1State tag;
        crypto1_init(&tag, key);
        crypto1_word(&tag, uid ^ nt, 0);

        for (int i = 0; i < 4; i++) {
            const uint8_t nrPlain = (uint8_t)(crypto1_byte(&tag, nr[i], 1) ^ nr[i]);
            out->par[c][i] = (uint8_t)(crypto1_filter_bit(&tag) ^ oddparity(nrPlain));
        }

        for (int i = 0; i < 4; i++) {
            const uint8_t ks = crypto1_byte(&tag, 0, 0);
            const uint8_t arPlain = (uint8_t)(ks ^ ar[i]);
            out->par[c][4 + i] = (uint8_t)(crypto1_filter_bit(&tag) ^ oddparity(arPlain));
        }

        const uint8_t ksNibble = (uint8_t)(crypto1_byte(&tag, 0, 0) & 0x0F);
        out->ks[c] = ksNibble;
    }
    return true;
}

} // namespace

int main() {
    const uint64_t key = 0x1A2B3C4D5E6FULL;
    const uint32_t uid = 0x11223344;
    const uint32_t nt = 0x12345678;
    const uint32_t arEnc = 0xFACECAFE;
    const uint32_t prefix = 0xDEADBEEF & 0xFFFFFF1F;

    Sample sample;
    if (!makeSample(key, uid, nt, prefix, arEnc, &sample)) {
        printf("FAIL: sample generation\n");
        return 1;
    }

    uint64_t keys[16] = {0};
    const int n = mfc_darkside::recoverKeys(prefix, arEnc, sample.ks, sample.par, uid, nt, keys, 16);
    if (n <= 0) {
        printf("FAIL: solver returned %d\n", n);
        return 1;
    }

    for (int i = 0; i < n; i++) {
        if (keys[i] == key) {
            printf("PASS: recovered key %012llX (%d candidates)\n",
                   (unsigned long long)keys[i], n);
            return 0;
        }
    }

    printf("FAIL: key not in %d candidates:", n);
    for (int i = 0; i < n; i++) printf(" %012llX", (unsigned long long)keys[i]);
    printf("\n");
    return 1;
}
