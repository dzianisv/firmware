#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t mfc_nonce_prng_successor(uint32_t x, uint32_t n);
uint8_t mfc_nonce_oddparity(uint8_t b);
uint32_t mfc_nonce_distance(uint32_t prev_nt, uint32_t next_nt, uint32_t *dist_out);
uint8_t mfc_nonce_parity_filter_ok(uint32_t nt_plaintext, uint8_t enc_nt[4]);
void mfc_nonce_encrypt_trail(uint32_t key_state_odd, uint32_t key_state_even, const uint8_t *plain, uint8_t *enc_out, uint8_t *par_out, size_t len);

#ifdef __cplusplus
}
#endif
