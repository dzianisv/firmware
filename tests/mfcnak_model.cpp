// Host-side calibration for a 4-bit NAK oracle.
//
// The clone answers a wrong-key authentication with a 4-bit NAK (or silence).
// If that nibble is a deterministic function of the bytes we transmit and the
// key, then one capture is 4 bits of key information and a handful of captures
// identify a 48-bit key that only 32 keystream bits constrain (~66,000
// candidates). This program decides whether that is true by testing every
// plausible convention against real captures from a sector whose key we know.
//
// Usage: mfcnak_model <captures.txt> [uidHex]
//   captures.txt lines: "wire nt=... wire=<32hex> raw=<10hex> bits=4 ..."
//   (the exact line `rfid mfcwire` prints)
//
// It prints every model that reproduces all captures, or says none did.
//
// STATUS 2026-11-06: never run against real captures, because the cheaper test
// already killed the idea. 480 shaped probes produced no 36-bit frame at all
// (hits36=0): every "AT mismatch" was a 4-bit NAK misread as a longer frame.
// The nibble therefore carries no recoverable key information on this card, and
// a 32-bit keystream still leaves ~65,536 candidates that only real auth
// exchanges can separate. Kept as the tool that would settle it for a different
// card, not as evidence for this one.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include "crypto1.h"

namespace {

struct Capture {
    uint32_t nt = 0;
    uint8_t wire[16] = {0};
    uint8_t raw[5] = {0};
    int bits = 0;
};

bool parseHexBytes(const std::string &s, uint8_t *out, size_t n) {
    if (s.size() < n * 2) return false;
    for (size_t i = 0; i < n; i++) {
        char b[3] = {s[i * 2], s[i * 2 + 1], 0};
        char *end = nullptr;
        long v = strtol(b, &end, 16);
        if (end != b + 2) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

// Pull "<key>=<hex>" out of a log line.
bool fieldHex(const std::string &line, const char *key, std::string *out) {
    const std::string k = std::string(key) + "=";
    size_t p = line.find(k);
    if (p == std::string::npos) return false;
    p += k.size();
    while (p < line.size() && line[p] == ' ') p++;
    size_t e = p;
    while (e < line.size() && isxdigit((unsigned char)line[e])) e++;
    if (e == p) return false;
    *out = line.substr(p, e - p);
    return true;
}

// How the card is assumed to process the wire before it answers.
enum FeedAr { AR_ZEROS, AR_ENCRYPTED, AR_NONE };
enum FeedNr { NR_ENCRYPTED, NR_RAW, NR_NONE };
enum Bits { BITS_CLOCK, BITS_PEEK };

struct Model {
    FeedAr feedAr;
    FeedNr feedNr;
    uint8_t plain;
    bool msbFirst;
    Bits bits;
    bool highNibble; // observed nibble stored in the high half of raw[0]
};

// What this model says the card would answer to `wire` if its key were `key`.
uint8_t predict(const Model &m, uint32_t uid, const Capture &c, const uint8_t key[6]) {
    uint64_t k = 0;
    for (int i = 0; i < 6; i++) k = (k << 8) | key[i];
    Crypto1State s;
    crypto1_init(&s, k);
    crypto1_word(&s, c.nt ^ uid, 0);

    if (m.feedNr != NR_NONE) {
        for (int i = 0; i < 4; i++) crypto1_byte(&s, c.wire[i], m.feedNr == NR_ENCRYPTED ? 1 : 0);
    }
    if (m.feedAr == AR_ENCRYPTED) {
        for (int i = 4; i < 8; i++) crypto1_byte(&s, c.wire[i], 1);
    } else if (m.feedAr == AR_ZEROS) {
        for (int i = 0; i < 4; i++) crypto1_byte(&s, 0, 0);
    }

    uint8_t ks = 0;
    for (int i = 0; i < 4; i++) {
        const uint8_t b = (m.bits == BITS_CLOCK) ? crypto1_bit(&s, 0, 0) : crypto1_filter_bit(&s);
        if (m.msbFirst) ks = (uint8_t)((ks << 1) | (b & 1));
        else ks = (uint8_t)(ks | ((b & 1) << i));
    }
    return (uint8_t)(m.plain ^ ks);
}

uint8_t observed(const Capture &c, bool highNibble) {
    return highNibble ? (uint8_t)(c.raw[0] >> 4) : (uint8_t)(c.raw[0] & 0x0F);
}

const char *feedArName(FeedAr f) {
    return f == AR_ZEROS ? "ar=zeros" : (f == AR_ENCRYPTED ? "ar=encrypted" : "ar=none");
}

} // namespace


// Self-test: synthesize a capture line for a known key and model, in exactly the
// format the device prints. The analyzer must then find that model.
static int emitSynthetic(uint32_t uid, const char *keyHex, int modelIdx, const char *wireHex) {
    uint8_t key[6];
    if (strlen(keyHex) != 12 || !parseHexBytes(keyHex, key, 6)) return 2;
    Capture c;
    c.nt = 0x01200145;
    if (!parseHexBytes(wireHex, c.wire, 16)) return 2;
    const uint8_t plains[] = {0x5, 0x4, 0xA, 0xF};
    // Model index follows the analyzer's loop order: fa, fn, bits, plain, nibble.
    const int total = 3 * 3 * 2 * 4 * 2;
    if (modelIdx < 0 || modelIdx >= total) return 2;
    int i = modelIdx;
    const int hi = i % 2; i /= 2;
    const int pl = i % 4; i /= 4;
    const int bs = i % 2; i /= 2;
    const int fn = i % 3; i /= 3;
    const int fa = i % 3;
    Model m{(FeedAr)fa, (FeedNr)fn, plains[pl], bs == 0, BITS_CLOCK, hi != 0};
    const uint8_t nak = predict(m, uid, c, key);
    c.raw[0] = m.highNibble ? (uint8_t)(nak << 4) : nak;
    printf("wire nt=%08X wire=", c.nt);
    for (int b = 0; b < 16; b++) printf("%02X", c.wire[b] & (b < 8 ? 0xFF : 1));
    printf(" rx=00000000 par=0000 raw=");
    for (int b = 0; b < 5; b++) printf("%02X", c.raw[b]);
    printf(" bits=4 err=40 try=1\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <captures.txt> [uidHex]\n", argv[0]);
        return 2;
    }
    uint32_t uid = 0x1F47B5D9u;
    if (argc >= 5 && strcmp(argv[1], "--emit") == 0)
        return emitSynthetic(uid, argv[2], atoi(argv[3]), argv[4]);
    if (argc > 2) uid = (uint32_t)strtoul(argv[2], nullptr, 16);

    FILE *f = fopen(argv[1], "r");
    if (!f) { perror(argv[1]); return 2; }

    std::vector<Capture> caps;
    char buf[1024];
    while (fgets(buf, sizeof(buf), f)) {
        std::string line(buf);
        if (line.find("bits=4") == std::string::npos) continue;
        std::string ntS, wireS, rawS;
        if (!fieldHex(line, "nt", &ntS) || !fieldHex(line, "wire", &wireS) ||
            !fieldHex(line, "raw", &rawS))
            continue;
        Capture c;
        c.nt = (uint32_t)strtoul(ntS.c_str(), nullptr, 16);
        if (!parseHexBytes(wireS, c.wire, 16)) continue;
        if (!parseHexBytes(rawS, c.raw, 5)) continue; // long form; short form below
        c.bits = 4;
        caps.push_back(c);
    }
    fclose(f);

    if (caps.empty()) {
        printf("no 4-bit captures parsed\n");
        return 1;
    }
    printf("captures=%zu uid=%08X\n", caps.size(), uid);
    for (size_t i = 0; i < caps.size(); i++) {
        printf("  #%zu nt=%08X wire=", i, caps[i].nt);
        for (int b = 0; b < 8; b++) printf("%02X", caps[i].wire[b]);
        printf(" raw0=%02X low=%X high=%X\n", caps[i].raw[0], caps[i].raw[0] & 0x0F,
               caps[i].raw[0] >> 4);
    }

    // Any two captures with the same wire are duplicates for our purpose: the
    // card must answer the same nibble, so disagreement kills the oracle.
    for (size_t i = 0; i < caps.size(); i++)
        for (size_t j = i + 1; j < caps.size(); j++)
            if (memcmp(caps[i].wire, caps[j].wire, 8) == 0 &&
                (caps[i].raw[0] & 0x0F) != (caps[j].raw[0] & 0x0F))
                printf("WARNING: same wire answered %X and %X — not deterministic\n",
                       caps[i].raw[0] & 0x0F, caps[j].raw[0] & 0x0F);

    printf("\n-- models (need a known key to score) --\n");
    if (argc < 4) {
        printf("pass the known 12-hex key as the third argument to score models\n");
        return 0;
    }
    uint8_t key[6];
    if (strlen(argv[3]) != 12 || !parseHexBytes(argv[3], key, 6)) {
        fprintf(stderr, "key must be 12 hex chars\n");
        return 2;
    }

    const uint8_t plains[] = {0x5, 0x4, 0xA, 0xF};
    int winners = 0;
    for (int fa = 0; fa < 3; fa++)
    for (int fn = 0; fn < 3; fn++)
    for (int bs = 0; bs < 2; bs++)
    for (int pl = 0; pl < 4; pl++)
    for (int hi = 0; hi < 2; hi++) {
        Model m{(FeedAr)fa, (FeedNr)fn, plains[pl], bs == 0, BITS_CLOCK, hi != 0};
        int hit = 0;
        for (const auto &c : caps) {
            if (predict(m, uid, c, key) == observed(c, m.highNibble)) hit++;
        }
        if (hit == (int)caps.size()) {
            winners++;
            printf("MATCH %s %s plain=%X %s raw0.%s\n", feedArName(m.feedAr),
                   m.feedNr == NR_ENCRYPTED ? "nr=enc" : (m.feedNr == NR_RAW ? "nr=raw" : "nr=none"), m.plain,
                   m.msbFirst ? "msb-first" : "lsb-first", m.highNibble ? "hi" : "lo");
        }
    }
    if (!winners) printf("no model matched all captures\n");
    return winners ? 0 : 1;
}
