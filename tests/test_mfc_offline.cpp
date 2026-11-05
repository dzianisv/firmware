// Host tests for the offline oracle (mfc_offline). No hardware.
//
// These catch plumbing only: a synthetic exchange is generated for a random key
// with each model, and the enumerator must return exactly that key. They are NOT
// proof that the card follows any model — that is what a real capture decides.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <random>

#include "crypto1.h"
#include "mfc_flipper.h"
#include "mfc_offline.h"

static int g_failures = 0;

#define CHECK(cond, ...)                                                                       \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                                         \
            printf(__VA_ARGS__);                                                               \
            printf("\n");                                                                      \
            g_failures++;                                                                      \
        }                                                                                      \
    } while (0)

static uint64_t keyWord(const uint8_t key[6]) {
    uint64_t k = 0;
    for (int i = 0; i < 6; i++) k = (k << 8) | key[i];
    return k;
}

// Build the capture a card would produce for `key` under `model`, plus the
// keystream window (ntEnc) and nonce parity bits that mfc_flipper needs.
static mfc_offline::Sample synthesize(
    uint32_t uid, uint32_t nt, const uint8_t key[6], const uint8_t wire[8],
    const uint8_t wirePar[8], int model
) {
    mfc_offline::Sample s;
    s.uid = uid;
    s.nt = nt;
    memcpy(s.wire, wire, 8);
    memcpy(s.wirePar, wirePar, 8);

    Crypto1State c;
    crypto1_init(&c, keyWord(key));
    // The card feeds nt ^ uid byte by byte; the parity bit it transmits after
    // each of the first three bytes rides on the filter output at that point.
    const uint32_t v = nt ^ uid;
    uint32_t ks = 0;
    uint8_t parBits = 0;
    for (int i = 0; i < 4; i++) {
        const uint8_t b = (uint8_t)(v >> (24 - 8 * i));
        ks = (ks << 8) | crypto1_byte(&c, b, 0);
        if (i < 3) {
            const uint8_t p = crypto1_filter_bit(&c);
            parBits |= (uint8_t)((p ^ nfc_oddparity((uint8_t)(nt >> (24 - 8 * i)))) << i);
        }
    }
    s.ntEnc = nt ^ ks;
    s.ntPar = parBits;

    mfc_offline::predict(s, key, model, s.rx, s.rxPar);
    s.hasRxParity = true;
    return s;
}

static void fillRandomKey(std::mt19937 &rng, uint8_t key[6]) {
    for (int i = 0; i < 6; i++) key[i] = (uint8_t)(rng() & 0xFF);
}

int main() {
    std::mt19937 rng(0xC0FFEEu);
    const uint32_t uid = 0x1F47B5D9u;
    const uint32_t nt = 0x01200145u; // the lab card's static nonce

    uint8_t wire[8], wirePar[8];
    for (int i = 0; i < 8; i++) {
        wire[i] = (uint8_t)(rng() & 0xFF);
        wirePar[i] = (uint8_t)(rng() & 1);
    }

    for (int model = 0; model < mfc_offline::ModelCount; model++) {
        uint8_t key[6];
        fillRandomKey(rng, key);
        const mfc_offline::Sample s = synthesize(uid, nt, key, wire, wirePar, model);

        // The true key must reproduce the capture bit for bit.
        CHECK(mfc_offline::matches(s, key, model), "model %s: true key rejected",
              mfc_offline::modelName(model));
        CHECK(mfc_offline::bitScore(s, key, model) == 32, "model %s: score %d != 32",
              mfc_offline::modelName(model), mfc_offline::bitScore(s, key, model));

        // 10,000 random wrong keys must be rejected. The plaintext-answer model
        // is exempt: it returns the same bytes for every key and cannot identify
        // one, which is exactly why enumerate() refuses it.
        if (model != mfc_offline::ModelPlainAnswer) {
            int accepted = 0;
            for (int i = 0; i < 10000; i++) {
                uint8_t wrong[6];
                fillRandomKey(rng, wrong);
                if (memcmp(wrong, key, 6) == 0) continue;
                if (mfc_offline::matches(s, wrong, model)) accepted++;
            }
            CHECK(accepted == 0, "model %s: %d/10000 wrong keys accepted",
                  mfc_offline::modelName(model), accepted);
        }

        if (model == mfc_offline::ModelPlainAnswer) {
            static uint8_t out[8][6];
            const mfc_offline::EnumResult r = mfc_offline::enumerate(s, model, out, 8);
            CHECK(r.solver == (int)mfc_flipper::Result::InvalidInput,
                  "plain-answer model must be refused by enumerate(), got %d", r.solver);
            printf("model %-14s refused (carries no key information)\n",
                   mfc_offline::modelName(model));
            continue;
        }

        // The enumerator must find the key and reject everything else.
        static uint8_t out[64][6];
        const mfc_offline::EnumResult r = mfc_offline::enumerate(s, model, out, 64);
        CHECK(r.solver == (int)mfc_flipper::Result::Ok, "model %s: solver result %d",
              mfc_offline::modelName(model), r.solver);
        CHECK(r.survivors == 1, "model %s: %d survivors, expected exactly 1",
              mfc_offline::modelName(model), r.survivors);
        if (r.survivors == 1) {
            CHECK(memcmp(out[0], key, 6) == 0, "model %s: survivor is not the true key",
                  mfc_offline::modelName(model));
        }
        printf(
            "model %-14s candidates=%d survivors=%d\n",
            mfc_offline::modelName(model),
            r.candidates,
            r.survivors
        );
    }

    // A capture from one model must NOT be explained by another model. If two
    // models ever collide on the same capture, calibration cannot pick one.
    uint8_t key[6];
    fillRandomKey(rng, key);
    for (int truth = 0; truth < mfc_offline::ModelCount; truth++) {
        const mfc_offline::Sample s = synthesize(uid, nt, key, wire, wirePar, truth);
        for (int other = 0; other < mfc_offline::ModelCount; other++) {
            if (other == truth) continue;
            if (mfc_offline::matches(s, key, other)) {
                printf(
                    "note: model %s explains a %s capture (models are not separable on "
                    "this wire)\n",
                    mfc_offline::modelName(other),
                    mfc_offline::modelName(truth)
                );
            }
        }
    }

    // feedSearch must recover the clock count that produced a nr+ar capture.
    {
        const mfc_offline::Sample s =
            synthesize(uid, nt, key, wire, wirePar, mfc_offline::ModelNrThenAr);
        int bits[8] = {0};
        const int n = mfc_offline::feedSearch(s, key, false, 96, bits, 8);
        CHECK(n > 0, "feedSearch: no clock count reproduces a nr+ar capture");
        bool saw64 = false;
        for (int i = 0; i < n && i < 8; i++) saw64 = saw64 || (bits[i] == 64);
        CHECK(saw64, "feedSearch: 64 clocks missing for a nr+ar capture (n=%d)", n);
        printf("feedSearch(nr+ar) -> %d match(es), first=%d\n", n, n > 0 ? bits[0] : -1);
    }

    if (g_failures) {
        printf("mfc_offline: %d FAILURE(S)\n", g_failures);
        return 1;
    }
    printf("mfc_offline: all checks passed\n");
    return 0;
}
