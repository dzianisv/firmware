// Static-nonce enumeration: a card that repeats one nonce leaks exactly one
// keystream window, so the key is underdetermined. Verify that the real key is
// among the candidates and that an accepting sink stops the search on it.
#include <cstdio>
#include <vector>
#include "crypto1.h"
#include "mfc_recovery.h"

static std::vector<uint64_t> seen;
static uint64_t acceptKey;
static uint8_t accepted[6];
static int acceptedCount;

static uint64_t pack(const uint8_t key[6]) {
    uint64_t v = 0;
    for (int i = 0; i < 6; i++) v = (v << 8) | key[i];
    return v;
}

static bool collect(const uint8_t key[6], void *) {
    seen.push_back(pack(key));
    return false;
}

static bool accept(const uint8_t key[6], void *) {
    acceptedCount++;
    if (pack(key) != acceptKey) return false;
    for (int i = 0; i < 6; i++) accepted[i] = key[i];
    return true;
}

static void parityBits(uint32_t nt, uint32_t ks, uint8_t out[3]) {
    for (int i = 0; i < 3; i++) {
        const uint8_t byte = (uint8_t)(nt >> (24 - 8 * i));
        const uint8_t ksBit = (uint8_t)((ks >> (24 ^ (8 * i + 8))) & 1u);
        out[i] = (uint8_t)(ksBit ^ nfc_oddparity(byte));
    }
}

static int runCase(const char *name, uint32_t uid, uint64_t key, uint32_t nt) {
    Crypto1State s;
    crypto1_init(&s, key);
    const uint32_t ks = crypto1_word(&s, nt ^ uid, 0);
    const mfc_recovery::Sample sample{nt, nt ^ ks};
    uint8_t par[3];
    parityBits(nt, ks, par);
    const uint8_t parity = (uint8_t)(par[0] | (par[1] << 1) | (par[2] << 2));

    seen.clear();
    auto r = mfc_recovery::enumerateKeys(uid, sample, -1, collect, nullptr);
    bool present = false;
    for (uint64_t v : seen) present |= v == key;

    acceptKey = key;
    acceptedCount = 0;
    auto r2 = mfc_recovery::enumerateKeys(uid, sample, -1, accept, nullptr);
    const bool hit = r2 == mfc_recovery::Result::Found && pack(accepted) == key;

    printf("%s: nt=%08X ks=%08X parity=%u candidates=%zu present=%d accept=%d\n", name, nt, ks,
           parity, seen.size(), present ? 1 : 0, hit ? 1 : 0);
    const bool ok = r == mfc_recovery::Result::NotFound && present && hit && seen.size() > 0 &&
                    seen.size() < 200000;
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    return ok ? 0 : 1;
}

int main() {
    int fails = 0;
    fails += runCase("lab card blk0 key", 0x1F47B5D9, 0xA0A1A2A3A4A5ULL, 0x01200145);
    fails += runCase("lab card blk7 key", 0x1F47B5D9, 0x112233445566ULL, 0x01200145);
    fails += runCase("second nonce", 0xDEADBEEF, 0xD3F7D3F7D3F7ULL, 0x89ABCDEF);
    printf(fails ? "FAIL: static-nonce enumeration\n" : "PASS: all static-nonce cases\n");
    return fails ? 1 : 0;
}
