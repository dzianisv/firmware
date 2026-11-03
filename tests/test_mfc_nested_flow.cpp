// Offline end-to-end test of the nested acquisition pipeline:
// weak-PRNG nonce simulation -> distance calibration -> target capture ->
// parity-filtered prediction -> mfc_recovery::recover().
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/modules/rfid/crypto1.h"
#include "../src/modules/rfid/mfc_nonce.h"
#include "../src/modules/rfid/mfc_recovery.h"
#include "../src/modules/rfid/mfc_nested.h"

namespace {

uint16_t bswap16(uint16_t v) { return (uint16_t)((v >> 8) | (v << 8)); }

uint16_t step16(uint16_t v) {
    return (uint16_t)((v >> 1) | (((v ^ (v >> 2) ^ (v >> 3) ^ (v >> 5)) & 1u) << 15));
}

// Weak MIFARE PRNG shape: upper and lower halves are 16 LFSR steps apart.
uint32_t make_nonce(uint16_t state) {
    uint16_t lo = state;
    for (int i = 0; i < 16; i++) lo = step16(lo);
    return ((uint32_t)bswap16(state) << 16) | bswap16(lo);
}

struct SimCard {
    uint16_t state;
    uint32_t uid;
    uint64_t target_key;
    uint64_t known_key;

    uint32_t next_nonce() {
        uint32_t nt = make_nonce(state);
        state = step16(state);
        return nt;
    }

    void advance(uint32_t steps) {
        while (steps--) state = step16(state);
    }

    // The card clocks Nt ^ uid into the cipher while emitting the encrypted
    // nonce, so the reader can mirror it with crypto1_word(encNt ^ uid, 1).
    void nested_nonce(uint64_t key, uint32_t nt, uint32_t *enc_out, uint8_t par[3]) {
        Crypto1State c;
        crypto1_init(&c, key);
        const uint32_t ks = crypto1_word(&c, nt ^ uid, 0);
        *enc_out = nt ^ ks;
        const uint8_t plain[4] = {(uint8_t)(nt >> 24), (uint8_t)(nt >> 16), (uint8_t)(nt >> 8),
                                  (uint8_t)nt};
        par[0] = (uint8_t)(nfc_oddparity(plain[0]) ^ ((ks >> 16) & 1u));
        par[1] = (uint8_t)(nfc_oddparity(plain[1]) ^ ((ks >> 8) & 1u));
        par[2] = (uint8_t)(nfc_oddparity(plain[2]) ^ (ks & 1u));
    }
};

struct Capture {
    uint32_t nt1;
    uint32_t enc_nt;
    uint8_t par[3];
};

int run_case(uint32_t expected_dist) {
    SimCard card{0x1234, 0x11223344, 0x1a2b3c4d5e6fULL, 0xffffffffffffULL};

    // Calibration: first auth (plaintext Nt) then a nested auth to the same
    // known block. The reader knows this key, so it can decrypt Nt2 and
    // measure the PRNG distance between two nonces separated by
    // expected_dist steps.
    uint32_t nt1 = card.next_nonce();
    card.advance(expected_dist - 1);
    uint32_t nt2 = card.next_nonce();
    uint32_t enc2;
    uint8_t par2[3];
    card.nested_nonce(card.known_key, nt2, &enc2, par2);

    Crypto1State known;
    crypto1_init(&known, card.known_key);
    uint32_t nt2_dec = enc2 ^ crypto1_word(&known, enc2 ^ card.uid, 1);
    if (nt2_dec != nt2) {
        printf("FAIL: dist %u nested known-key decryption %08X != %08X\n", expected_dist, nt2_dec,
               nt2);
        return 1;
    }

    uint32_t dist = 0;
    if (mfc_nonce_distance(nt1, nt2, &dist) != 0) {
        printf("FAIL: dist %u no PRNG distance\n", expected_dist);
        return 1;
    }
    if (dist != expected_dist) {
        printf("FAIL: expected distance %u, got %u\n", expected_dist, dist);
        return 1;
    }

    // Two target captures, each in a fresh session.
    Capture cap[2];
    for (int i = 0; i < 2; i++) {
        cap[i].nt1 = card.next_nonce();
        card.advance(expected_dist - 1);
        uint32_t nt = card.next_nonce();
        card.nested_nonce(card.target_key, nt, &cap[i].enc_nt, cap[i].par);
        if (!mfc_nonce_parity_filter_ok(nt, cap[i].enc_nt, cap[i].par)) {
            printf("FAIL: dist %u parity filter rejected the true nonce\n", expected_dist);
            return 1;
        }
        uint32_t predicted = prng_successor(cap[i].nt1, dist);
        if (predicted != nt) {
            printf("FAIL: dist %u prediction %08X != %08X\n", expected_dist, predicted, nt);
            return 1;
        }
    }

    // The filter must reject most wrong PRNG offsets (3 parity bits -> ~1/8).
    unsigned false_accepts = 0;
    for (int d = -14; d <= 14; d++) {
        if (d == 0) continue;
        const int off = (int)dist + d;
        if (off <= 0) continue;
        uint32_t nt = prng_successor(cap[0].nt1, (uint32_t)off);
        if (mfc_nonce_parity_filter_ok(nt, cap[0].enc_nt, cap[0].par)) false_accepts++;
    }
    if (false_accepts > 10) {
        printf("FAIL: dist %u parity filter too permissive (%u/28)\n", expected_dist,
               false_accepts);
        return 1;
    }

    mfc_recovery::Sample samples[2];
    for (int i = 0; i < 2; i++) {
        samples[i].nt = prng_successor(cap[i].nt1, dist);
        samples[i].encrypted = cap[i].enc_nt;
    }

    uint8_t key[6] = {0};
    mfc_recovery::Result r = mfc_recovery::recover(card.uid, samples[0], samples[1], key);
    if (r != mfc_recovery::Result::Found) {
        printf("FAIL: dist %u solver result %d\n", expected_dist, (int)r);
        return 1;
    }
    uint64_t recovered = 0;
    for (int i = 0; i < 6; i++) recovered = (recovered << 8) | key[i];
    if (recovered != card.target_key) {
        printf("FAIL: dist %u recovered %012llX != %012llX\n", expected_dist,
               (unsigned long long)recovered, (unsigned long long)card.target_key);
        return 1;
    }

    // Fresh authentication with the recovered key: reader and card must
    // agree on Nr, then the card's At must decrypt to the expected PRNG word.
    Crypto1State card_c, reader_c;
    crypto1_init(&card_c, recovered);
    crypto1_init(&reader_c, recovered);
    uint32_t nt_fresh = card.next_nonce();
    uint32_t ar_plain = prng_successor(nt_fresh, 64);
    uint32_t at_plain = prng_successor(nt_fresh, 96);
    uint32_t nr = 0x89abcdef;

    crypto1_word(&reader_c, nt_fresh ^ card.uid, 0);
    uint8_t nr_enc[4];
    for (int i = 0; i < 4; i++) {
        uint8_t b = (uint8_t)(nr >> (24 - 8 * i));
        nr_enc[i] = (uint8_t)(crypto1_byte(&reader_c, b, 0) ^ b);
    }

    crypto1_word(&card_c, nt_fresh ^ card.uid, 0);
    uint32_t nr_dec = 0;
    for (int i = 0; i < 4; i++)
        nr_dec = (nr_dec << 8) | (uint8_t)(crypto1_byte(&card_c, nr_enc[i], 1) ^ nr_enc[i]);
    if (nr_dec != nr) {
        printf("FAIL: dist %u card did not decrypt Nr\n", expected_dist);
        return 1;
    }

    // After Nr, Ar and At advance Crypto1 with zero input, as do subsequent
    // encrypted commands. Feeding their plaintext causes state divergence.
    uint8_t ar_enc[4];
    for (int i = 0; i < 4; i++)
        ar_enc[i] = (uint8_t)(crypto1_byte(&reader_c, 0, 0) ^ (uint8_t)(ar_plain >> (24 - 8 * i)));
    uint32_t ar_dec = 0;
    for (int i = 0; i < 4; i++)
        ar_dec = (ar_dec << 8) | (uint8_t)(crypto1_byte(&card_c, 0, 0) ^ ar_enc[i]);
    if (ar_dec != ar_plain) {
        printf("FAIL: dist %u card did not decrypt Ar\n", expected_dist);
        return 1;
    }

    uint8_t at_enc[4];
    for (int i = 0; i < 4; i++)
        at_enc[i] = (uint8_t)(crypto1_byte(&card_c, 0, 0) ^ (uint8_t)(at_plain >> (24 - 8 * i)));

    uint32_t at_dec = 0;
    for (int i = 0; i < 4; i++)
        at_dec = (at_dec << 8) | (uint8_t)(crypto1_byte(&reader_c, 0, 0) ^ at_enc[i]);
    if (at_dec != at_plain) {
        printf("FAIL: dist %u fresh authentication answer mismatch %08X != %08X\n", expected_dist,
               at_dec, at_plain);
        return 1;
    }

    printf("PASS: dist=%u false_accepts=%u key=%012llX fresh-auth=OK\n", dist, false_accepts,
           (unsigned long long)recovered);
    return 0;
}


// Exercise the exact device path: mfc_nested::solve() over parity-filtered
// PRNG-distance candidates, with a PRNG distance that can wobble between
// captures like a real card.
int run_solve_case(uint32_t median, int spread, unsigned maxCalls) {
    SimCard card{0x2b7e, 0xdeadbeef, 0x0123456789abULL, 0xa0a1a2a3a4a5ULL};
    const int kCaptures = 6;

    mfc_nested::Capture caps[kCaptures];
    for (int i = 0; i < kCaptures; i++) {
        const uint32_t d = (uint32_t)((int)median + ((i % 3) - 1) * spread);
        caps[i].nt1 = card.next_nonce();
        card.advance(d - 1);
        const uint32_t nt = card.next_nonce();
        card.nested_nonce(card.target_key, nt, &caps[i].enc, caps[i].par);
    }

    uint8_t key[6] = {0};
    unsigned calls = 0;
    const auto r = mfc_nested::solve(card.uid, caps, kCaptures, median, 20, key, nullptr, nullptr,
                                     &calls);
    if (r != mfc_recovery::Result::Found) {
        printf("FAIL: solve median=%u spread=%d result %d calls=%u\n", median, spread, (int)r,
               calls);
        return 1;
    }
    uint64_t recovered = 0;
    for (int i = 0; i < 6; i++) recovered = (recovered << 8) | key[i];
    if (recovered != card.target_key) {
        printf("FAIL: solve median=%u spread=%d recovered %012llX\n", median, spread,
               (unsigned long long)recovered);
        return 1;
    }
    if (calls > maxCalls) {
        printf("FAIL: solve median=%u spread=%d used %u solver calls (budget %u)\n", median, spread,
               calls, maxCalls);
        return 1;
    }

    // A window that cannot contain the true distance must not invent a key.
    uint8_t bad[6] = {0};
    unsigned badCalls = 0;
    const auto miss =
        mfc_nested::solve(card.uid, caps, 2, median + 4000, 0, bad, nullptr, nullptr, &badCalls);
    if (miss == mfc_recovery::Result::Found) {
        printf("FAIL: solve accepted a wrong distance window\n");
        return 1;
    }

    printf("PASS: solve median=%u spread=%d calls=%u key=%012llX window-reject=%d\n", median,
           spread, calls, (unsigned long long)recovered, (int)miss);
    return 0;
}

}  // namespace

int main() {
    const uint32_t distances[] = {1, 15, 31};
    for (uint32_t d : distances) {
        if (run_case(d) != 0) return 1;
    }
    // Constant PRNG advance resolves on the first distance, one solver call.
    if (run_solve_case(256, 0, 1) != 0) return 1;
    // Jittered advance: two of six captures share the median distance.
    if (run_solve_case(256, 2, 4) != 0) return 1;
    if (run_solve_case(1024, 4, 6) != 0) return 1;
    printf("PASS: all distances\n");
    return 0;
}
