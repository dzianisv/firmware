// Host tool for the MIFARE Classic offline oracle (mfc_offline).
//
// Two jobs:
//   diagnose  — given a real capture and a KNOWN key, say which cipher
//               convention reproduces the card's answer. This is calibration:
//               it selects the model by measurement instead of by guess.
//   enumerate — given a real capture and an UNKNOWN key, list the candidate keys
//               whose predicted answer equals the capture. No card exchange per
//               candidate.
//
// Input is one capture, given as key=value arguments:
//   --uid 1F47B5D9 --nt 01200145 --enc 01200145 --par 0
//   --wire <32 hex> --rx <8 hex> [--rxpar 0101]
// `--enc` is the same nonce encrypted under the target key (keystream window).
// It is required by enumerate and ignored by diagnose.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto1.h"
#include "mfc_flipper.h"
#include "mfc_offline.h"

namespace {

void usage() {
    fprintf(stderr,
            "usage: mfc_offline_tool <diagnose|enumerate> --uid <8hex> --nt <8hex> "
            "--enc <8hex> --par <0-7>\n"
            "                           --wire <32hex> --rx <8hex> [--rxpar <4 bits>]\n"
            "       diagnose also needs --key <12hex>\n"
            "       enumerate takes [--model all|0-5] [--max 8]\n");
}

bool parseHex(const char *s, uint8_t *out, size_t bytes) {
    if (strlen(s) != bytes * 2) return false;
    for (size_t i = 0; i < bytes; i++) {
        unsigned v = 0;
        if (sscanf(s + i * 2, "%2x", &v) != 1) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

bool parseU32(const char *s, uint32_t *out) {
    uint8_t b[4];
    if (!parseHex(s, b, 4)) return false;
    *out = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
    return true;
}

void printKey(const uint8_t key[6]) {
    for (int i = 0; i < 6; i++) printf("%02X", key[i]);
}

double seconds(clock_t from, clock_t to) { return (double)(to - from) / CLOCKS_PER_SEC; }

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 2;
    }
    const bool diagnose = strcmp(argv[1], "diagnose") == 0;
    const bool enumerateMode = strcmp(argv[1], "enumerate") == 0;
    if (!diagnose && !enumerateMode) {
        usage();
        return 2;
    }

    mfc_offline::Sample s;
    uint8_t key[6] = {0};
    bool haveKey = false;
    int modelArg = diagnose ? 0 : -1; // -1 = all
    int maxOut = 8;
    const char *wireHex = nullptr, *rxHex = nullptr, *rxParStr = nullptr;

    for (int i = 2; i + 1 < argc; i += 2) {
        const char *k = argv[i];
        const char *v = argv[i + 1];
        if (!strcmp(k, "--uid")) {
            if (!parseU32(v, &s.uid)) { fprintf(stderr, "bad --uid\n"); return 2; }
        } else if (!strcmp(k, "--nt")) {
            if (!parseU32(v, &s.nt)) { fprintf(stderr, "bad --nt\n"); return 2; }
        } else if (!strcmp(k, "--enc")) {
            if (!parseU32(v, &s.ntEnc)) { fprintf(stderr, "bad --enc\n"); return 2; }
        } else if (!strcmp(k, "--par")) {
            s.ntPar = (uint8_t)atoi(v);
        } else if (!strcmp(k, "--wire")) {
            wireHex = v;
        } else if (!strcmp(k, "--rx")) {
            rxHex = v;
        } else if (!strcmp(k, "--rxpar")) {
            rxParStr = v;
        } else if (!strcmp(k, "--key")) {
            if (!parseHex(v, key, 6)) { fprintf(stderr, "bad --key\n"); return 2; }
            haveKey = true;
        } else if (!strcmp(k, "--model")) {
            modelArg = strcmp(v, "all") == 0 ? -1 : atoi(v);
        } else if (!strcmp(k, "--max")) {
            maxOut = atoi(v);
        } else {
            fprintf(stderr, "unknown option %s\n", k);
            return 2;
        }
    }
    if (!wireHex || !rxHex) {
        usage();
        return 2;
    }
    uint8_t wire[16];
    if (!parseHex(wireHex, wire, 16)) {
        fprintf(stderr, "bad --wire (need 32 hex chars: 8 data bytes then 8 parity bytes)\n");
        return 2;
    }
    memcpy(s.wire, wire, 8);
    for (int i = 0; i < 8; i++) s.wirePar[i] = (uint8_t)(wire[8 + i] & 1u);
    if (!parseHex(rxHex, s.rx, 4)) {
        fprintf(stderr, "bad --rx\n");
        return 2;
    }
    if (rxParStr) {
        if (strlen(rxParStr) != 4) {
            fprintf(stderr, "bad --rxpar (need 4 chars of 0/1)\n");
            return 2;
        }
        for (int i = 0; i < 4; i++) s.rxPar[i] = (uint8_t)(rxParStr[i] - '0');
        s.hasRxParity = true;
    }

    printf(
        "capture uid=%08X nt=%08X enc=%08X par=%u wire=%s rx=%s%s%s\n",
        s.uid,
        s.nt,
        s.ntEnc,
        s.ntPar,
        wireHex,
        rxHex,
        rxParStr ? " rxpar=" : "",
        rxParStr ? rxParStr : ""
    );

    if (diagnose) {
        if (!haveKey) {
            fprintf(stderr, "diagnose needs --key\n");
            return 2;
        }
        const uint32_t at = prng_successor(s.nt, 96);
        uint8_t plain[4] = {
            (uint8_t)(at >> 24), (uint8_t)(at >> 16), (uint8_t)(at >> 8), (uint8_t)at};
        printf("expected answer plaintext suc96(nt)=%02X%02X%02X%02X\n",
               plain[0], plain[1], plain[2], plain[3]);

        int hits = 0;
        for (int m = 0; m < mfc_offline::ModelCount; m++) {
            uint8_t rx[4], rxPar[4];
            mfc_offline::predict(s, key, m, rx, rxPar);
            const bool ok = mfc_offline::matches(s, key, m);
            if (ok) hits++;
            printf(
                "model %-14s predicted=%02X%02X%02X%02X par=%u%u%u%u score=%2d %s\n",
                mfc_offline::modelName(m),
                rx[0], rx[1], rx[2], rx[3],
                rxPar[0] & 1, rxPar[1] & 1, rxPar[2] & 1, rxPar[3] & 1,
                mfc_offline::bitScore(s, key, m),
                ok ? "MATCH" : "-"
            );
        }
        printf("models matching the capture: %d\n", hits);

        int bits[16] = {0};
        const int nFeed = mfc_offline::feedSearch(s, key, false, 96, bits, 16);
        printf("feedSearch(data bits only) matches=%d", nFeed);
        for (int i = 0; i < nFeed && i < 16; i++) printf(" k=%d", bits[i]);
        printf("\n");
        const int nFeedP = mfc_offline::feedSearch(s, key, true, 96, bits, 16);
        printf("feedSearch(data+parity bits) matches=%d", nFeedP);
        for (int i = 0; i < nFeedP && i < 16; i++) printf(" k=%d", bits[i]);
        printf("\n");
        const int nZero = mfc_offline::zeroFeedSearch(s, key, 256, bits, 16);
        printf("zeroFeedSearch matches=%d", nZero);
        for (int i = 0; i < nZero && i < 16; i++) printf(" k=%d", bits[i]);
        printf("\n");
        return hits > 0 ? 0 : 1;
    }

    // enumerate
    static uint8_t out[256][6];
    if (maxOut < 1) maxOut = 1;
    if (maxOut > 256) maxOut = 256;
    const int first = modelArg < 0 ? 0 : modelArg;
    const int last = modelArg < 0 ? mfc_offline::ModelCount - 1 : modelArg;
    int total = 0;
    for (int m = first; m <= last; m++) {
        if (m < 0 || m >= mfc_offline::ModelCount) continue;
        const clock_t t0 = clock();
        const mfc_offline::EnumResult r = mfc_offline::enumerate(s, m, out, maxOut);
        const double dt = seconds(t0, clock());
        printf(
            "model %-14s solver=%d candidates=%d survivors=%d wall=%.3fs\n",
            mfc_offline::modelName(m),
            r.solver,
            r.candidates,
            r.survivors,
            dt
        );
        for (int i = 0; i < r.stored; i++) {
            printf("  survivor[%d] ", i);
            printKey(out[i]);
            printf("\n");
        }
        total += r.survivors;
    }
    printf("total survivors: %d\n", total);
    return total > 0 ? 0 : 1;
}
