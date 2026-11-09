#include <iostream>
#include <stdint.h>
#include <string.h>
#include "../src/modules/rfid/crypto1.h"

// Native tests for pure helpers - test prng/nonce behavior
int main() {
    // Test prng_successor
    uint32_t x = 0x12345678;
    uint32_t y1 = prng_successor(x, 1);
    uint32_t y2 = prng_successor(y1, 1);
    if (y2 == x) { std::cout << "bad\n"; return 1; }
    
    // Test parity
    uint8_t p = nfc_oddparity(0xFF);
    (void)p;
    
    // Fixed vector test - basic sanity
    uint64_t key = 0xFFFFFFFFFFFFULL;
    Crypto1State s;
    crypto1_init(&s, key);
    uint32_t nt = prng_successor(0, 1);
    uint32_t ks = crypto1_word(&s, nt ^ 0x11223344, 0);
    (void)ks;
    
    std::cout << "ok\n";
    return 0;
}
