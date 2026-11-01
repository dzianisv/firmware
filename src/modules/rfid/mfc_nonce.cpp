#include "mfc_nonce.h"
#include "crypto1.h"
#include <string.h>

extern "C" {

uint32_t mfc_nonce_prng_successor(uint32_t x, uint32_t n) {
    return prng_successor(x, n);
}

uint8_t mfc_nonce_oddparity(uint8_t b) {
    return nfc_oddparity(b);
}

uint32_t mfc_nonce_distance(uint32_t prev_nt, uint32_t next_nt, uint32_t *dist_out) {
    if (!dist_out) return 1;
    uint32_t cur = prev_nt;
    for (uint32_t i = 1; i <= 0x10000u; i++) {
        cur = prng_successor(cur, 1);
        if (cur == next_nt) {
            *dist_out = i;
            return 0;
        }
    }
    *dist_out = 0;
    return 1;
}

uint8_t mfc_nonce_parity_filter_ok(uint32_t nt_plaintext, uint32_t enc_nt, const uint8_t raw_parity[3]) {
    if (!raw_parity) return 0;
    const uint32_t ks = nt_plaintext ^ enc_nt;
    const uint8_t p0 = nfc_oddparity((uint8_t)(nt_plaintext >> 24));
    const uint8_t p1 = nfc_oddparity((uint8_t)(nt_plaintext >> 16));
    const uint8_t p2 = nfc_oddparity((uint8_t)(nt_plaintext >> 8));
    return (p0 == (uint8_t)(raw_parity[0] ^ ((ks >> 16) & 1u))) &&
           (p1 == (uint8_t)(raw_parity[1] ^ ((ks >> 8) & 1u))) &&
           (p2 == (uint8_t)(raw_parity[2] ^ (ks & 1u)));
}

void mfc_nonce_encrypt_trail(uint32_t key_state_odd, uint32_t key_state_even, const uint8_t *plain,
                             uint8_t *enc_out, uint8_t *par_out, size_t len) {
    Crypto1State state = {key_state_odd, key_state_even};
    for (size_t i = 0; i < len; i++) {
        enc_out[i] = (uint8_t)(crypto1_byte(&state, 0, 0) ^ plain[i]);
        if (par_out) par_out[i] = (uint8_t)(crypto1_filter_bit(&state) ^ nfc_oddparity(plain[i]));
    }
}

}
