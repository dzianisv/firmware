#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t mfc_nonce_prng_successor(uint32_t x, uint32_t n);
uint8_t mfc_nonce_oddparity(uint8_t b);

// Returns 0 and writes the number of PRNG steps from prev_nt to next_nt when
// next_nt is reachable within one 16-bit period; returns 1 otherwise.
uint32_t mfc_nonce_distance(uint32_t prev_nt, uint32_t next_nt, uint32_t *dist_out);

// raw_parity[i] is the parity bit received after encrypted nonce byte i, as it
// came off the wire. The MIFARE card computes it as
//   raw_parity[i] = oddparity(plain_byte[i]) ^ keystream_bit(8*i + 8)
// so the check below only needs the candidate plaintext and the ciphertext.
uint8_t mfc_nonce_parity_filter_ok(uint32_t nt_plaintext, uint32_t enc_nt, const uint8_t raw_parity[3]);

void mfc_nonce_encrypt_trail(uint32_t key_state_odd, uint32_t key_state_even, const uint8_t *plain, uint8_t *enc_out, uint8_t *par_out, size_t len);

#ifdef __cplusplus
}
#endif
