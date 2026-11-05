#include "mfc_offline.h"

#include <string.h>

#include "crypto1.h"
#include "mfc_flipper.h"

namespace mfc_offline {

namespace {

const char *const kModelNames[ModelCount] = {
    "nr+ar",
    "nr+zeros",
    "nr-only",
    "nothing",
    "nr+ar+parity",
    "plain-answer",
};

uint64_t keyWord(const uint8_t key[6]) {
    uint64_t k = 0;
    for (int i = 0; i < 6; i++) k = (k << 8) | key[i];
    return k;
}

// Clock the cipher over the received wire the way the assumed model says the
// card does. Feeding ciphertext with is_encrypted=1 is identical to feeding the
// decrypted plaintext with is_encrypted=0, which is what the card does, so the
// wire bytes can be fed directly.
void advance(Crypto1State *c, const Sample &s, int model) {
    switch (model) {
        case ModelNrThenAr:
            for (int i = 0; i < 8; i++) crypto1_byte(c, s.wire[i], 1);
            break;
        case ModelNrThenZero:
            for (int i = 0; i < 4; i++) crypto1_byte(c, s.wire[i], 1);
            for (int i = 0; i < 4; i++) crypto1_byte(c, 0, 1);
            break;
        case ModelNrOnly:
            for (int i = 0; i < 4; i++) crypto1_byte(c, s.wire[i], 1);
            break;
        case ModelNothing:
        case ModelPlainAnswer:
            break;
        case ModelNrThenArParity:
            for (int i = 0; i < 8; i++) {
                for (int b = 0; b < 8; b++) crypto1_bit(c, (uint8_t)((s.wire[i] >> b) & 1u), 1);
                crypto1_bit(c, (uint8_t)(s.wirePar[i] & 1u), 1);
            }
            break;
        default:
            break;
    }
}

// The four keystream bytes and four parity bits the card uses for the answer.
// Byte parity follows the driver: the parity bit is the filter output after the
// data byte has been clocked out, and is not itself clocked.
void answerKeystream(Crypto1State *c, uint8_t ks[4], uint8_t ksPar[4]) {
    for (int i = 0; i < 4; i++) {
        ks[i] = crypto1_byte(c, 0, 0);
        ksPar[i] = crypto1_filter_bit(c);
    }
}

bool parityEqual(const Sample &s, const uint8_t rxPar[4]) {
    if (!s.hasRxParity) return true;
    for (int i = 0; i < 4; i++) {
        if ((uint8_t)(s.rxPar[i] & 1u) != (uint8_t)(rxPar[i] & 1u)) return false;
    }
    return true;
}

struct FilterCtx {
    const Sample *sample = nullptr;
    int model = 0;
    uint8_t(*out)[6] = nullptr;
    int maxOut = 0;
    EnumResult result;
};

bool filterSink(const uint8_t key[6], void *context) {
    auto *ctx = static_cast<FilterCtx *>(context);
    ctx->result.candidates++;
    if (!matches(*ctx->sample, key, ctx->model)) return false; // keep sweeping
    ctx->result.survivors++;
    if (ctx->result.stored < ctx->maxOut) {
        memcpy(ctx->out[ctx->result.stored], key, 6);
        ctx->result.stored++;
    }
    return false; // never stop early: the caller wants every survivor
}

} // namespace

const char *modelName(int model) {
    if (model < 0 || model >= ModelCount) return "?";
    return kModelNames[model];
}

bool predict(const Sample &s, const uint8_t key[6], int model, uint8_t rx[4], uint8_t rxPar[4]) {
    if (model < 0 || model >= ModelCount) return false;
    const uint32_t at = prng_successor(s.nt, 96);

    if (model == ModelPlainAnswer) {
        for (int i = 0; i < 4; i++) {
            rx[i] = (uint8_t)(at >> (24 - 8 * i));
            rxPar[i] = nfc_oddparity(rx[i]);
        }
        return true;
    }

    Crypto1State c;
    crypto1_init(&c, keyWord(key));
    crypto1_word(&c, s.nt ^ s.uid, 0);
    advance(&c, s, model);

    uint8_t ks[4], ksPar[4];
    answerKeystream(&c, ks, ksPar);
    for (int i = 0; i < 4; i++) {
        const uint8_t plain = (uint8_t)(at >> (24 - 8 * i));
        rx[i] = (uint8_t)(plain ^ ks[i]);
        rxPar[i] = (uint8_t)(nfc_oddparity(plain) ^ ksPar[i]);
    }
    return true;
}

bool matches(const Sample &s, const uint8_t key[6], int model) {
    uint8_t rx[4], rxPar[4];
    if (!predict(s, key, model, rx, rxPar)) return false;
    for (int i = 0; i < 4; i++) {
        if (rx[i] != s.rx[i]) return false;
    }
    return parityEqual(s, rxPar);
}

int bitScore(const Sample &s, const uint8_t key[6], int model) {
    uint8_t rx[4], rxPar[4];
    if (!predict(s, key, model, rx, rxPar)) return -1;
    int score = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t diff = (uint8_t)(rx[i] ^ s.rx[i]);
        for (int b = 0; b < 8; b++) {
            if ((diff & (1u << b)) == 0) score++;
        }
    }
    return score;
}

// Derive the 32 answer keystream bits the card must have produced, then ask
// which clock count from the post-nonce state reproduces them.
static uint32_t requiredKeystream(const Sample &s) {
    const uint32_t at = prng_successor(s.nt, 96);
    uint32_t ks = 0;
    for (int i = 0; i < 4; i++) {
        ks = (ks << 8) | (uint8_t)(s.rx[i] ^ (uint8_t)(at >> (24 - 8 * i)));
    }
    return ks;
}

static uint32_t readWord(Crypto1State *c) {
    uint32_t w = 0;
    for (int i = 0; i < 4; i++) w = (w << 8) | crypto1_byte(c, 0, 0);
    return w;
}

int feedSearch(
    const Sample &s, const uint8_t key[6], bool withParity, int maxBits, int *outBits, int maxOut
) {
    if (maxBits < 0) maxBits = 0;
    if (maxBits > 512) maxBits = 512;
    const uint32_t want = requiredKeystream(s);
    int found = 0;

    for (int k = 0; k <= maxBits; k++) {
        Crypto1State c;
        crypto1_init(&c, keyWord(key));
        crypto1_word(&c, s.nt ^ s.uid, 0);
        int fed = 0;
        for (int i = 0; i < 8 && fed < k; i++) {
            for (int b = 0; b < 8 && fed < k; b++, fed++) {
                crypto1_bit(&c, (uint8_t)((s.wire[i] >> b) & 1u), 1);
            }
            if (withParity && fed < k) {
                crypto1_bit(&c, (uint8_t)(s.wirePar[i] & 1u), 1);
                fed++;
            }
        }
        // Not enough wire bits to reach k: stop rather than feed padding.
        if (fed < k) break;
        if (readWord(&c) != want) continue;
        if (outBits && found < maxOut) outBits[found] = k;
        found++;
    }
    return found;
}

int zeroFeedSearch(
    const Sample &s, const uint8_t key[6], int maxBits, int *outBits, int maxOut
) {
    if (maxBits < 0) maxBits = 0;
    if (maxBits > 512) maxBits = 512;
    const uint32_t want = requiredKeystream(s);
    int found = 0;
    for (int k = 0; k <= maxBits; k++) {
        Crypto1State c;
        crypto1_init(&c, keyWord(key));
        crypto1_word(&c, s.nt ^ s.uid, 0);
        for (int i = 0; i < k; i++) crypto1_bit(&c, 0, 0);
        if (readWord(&c) != want) continue;
        if (outBits && found < maxOut) outBits[found] = k;
        found++;
    }
    return found;
}

EnumResult enumerate(const Sample &s, int model, uint8_t out[][6], int maxOut) {
    FilterCtx ctx;
    ctx.sample = &s;
    ctx.model = model;
    ctx.out = out;
    ctx.maxOut = maxOut > 0 ? maxOut : 0;
    if (s.ntPar > 7) {
        ctx.result.solver = (int)mfc_flipper::Result::InvalidInput;
        return ctx.result;
    }
    // A plaintext answer is the same for every key, so it cannot identify one.
    // Refusing it here stops a caller from reading "all candidates survived" as
    // a result.
    if (model == ModelPlainAnswer) {
        ctx.result.solver = (int)mfc_flipper::Result::InvalidInput;
        return ctx.result;
    }
    const mfc_flipper::Sample fs{s.uid, s.nt, s.ntEnc, s.ntPar};
    const mfc_flipper::Result r = mfc_flipper::enumerateKeys(fs, filterSink, &ctx);
    ctx.result.solver = (int)r;
    return ctx.result;
}

void buildReaderWire(
    uint32_t nt, uint32_t uid, const uint8_t key[6], uint32_t nr, uint8_t wire[16]
) {
    Crypto1State c;
    crypto1_init(&c, keyWord(key));
    crypto1_word(&c, nt ^ uid, 0);
    const uint32_t ar = prng_successor(nt, 64);
    for (int i = 0; i < 4; i++) {
        const uint8_t p = (uint8_t)(nr >> (24 - 8 * i));
        wire[i] = (uint8_t)(crypto1_byte(&c, p, 0) ^ p);
        wire[8 + i] = (uint8_t)(crypto1_filter_bit(&c) ^ nfc_oddparity(p));
    }
    for (int i = 0; i < 4; i++) {
        const uint8_t p = (uint8_t)(ar >> (24 - 8 * i));
        wire[4 + i] = (uint8_t)(crypto1_byte(&c, p, 0) ^ p);
        wire[12 + i] = (uint8_t)(crypto1_filter_bit(&c) ^ nfc_oddparity(p));
    }
    for (int i = 0; i < 8; i++) wire[8 + i] &= 1u;
}

} // namespace mfc_offline
