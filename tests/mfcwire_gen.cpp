// Generate a well-formed MIFARE Classic auth answer frame ("wire") for a chosen
// key and nr, so the device can replay exactly the same bytes for every candidate.
//
// Why this exists: `rfid mfcwire` takes the 16 bytes literally, and the bytes
// must look like a real reader's answer — correct per-byte parity — or the clone
// goes silent instead of answering with a NAK. Generating the frame on the host
// keeps it fixed across candidates while still looking legitimate to the card.
//
// Usage: mfcwire_gen <ntHex> <uidHex> <keyHex> <nrHex>
//   mfcwire_gen 01200145 1F47B5D9 000000000000 11111111
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include "mfc_offline.h"

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <ntHex> <uidHex> <keyHex(12)> <nrHex>\n", argv[0]);
        return 2;
    }
    const uint32_t nt = (uint32_t)strtoul(argv[1], nullptr, 16);
    const uint32_t uid = (uint32_t)strtoul(argv[2], nullptr, 16);
    const char *keyHex = argv[3];
    const uint32_t nr = (uint32_t)strtoul(argv[4], nullptr, 16);
    if (strlen(keyHex) != 12) {
        fprintf(stderr, "key must be 12 hex chars\n");
        return 2;
    }
    uint8_t key[6];
    for (int i = 0; i < 6; i++) {
        char b[3] = {keyHex[i * 2], keyHex[i * 2 + 1], 0};
        key[i] = (uint8_t)strtoul(b, nullptr, 16);
    }

    uint8_t wire[16] = {0};
    mfc_offline::buildReaderWire(nt, uid, key, nr, wire);
    for (int i = 0; i < 16; i++) printf("%02X", wire[i] & (i < 8 ? 0xFF : 0x01));
    printf("\n");
    return 0;
}
