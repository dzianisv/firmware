// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Origin (GPL-3.0), ported and adapted 2026-11-03:
//   * flipperdevices/flipperzero-firmware, lib/nfc/helpers/crypto1.c, commit
//     8427ec009812 — LF polynomials, filter, rollback, key extraction.
//   * flipperdevices/flipperzero-good-faps, mfkey/, commit 55328b486971 —
//     mfkey.h:16-23 (768 packed 24-bit states per MSB bucket),
//     mfkey_attack.c:53-280 (bounded per-band sweep, batch insertion, final
//     verify pass), mfkey_recovery.c:21-38 (binary-search join), :40-88
//     (in-place sort scratch), mfkey_state_expansion.c:18-140 (in-place
//     state expansion without a second table).
//   * local provenance: src/modules/rfid/mfc_recovery.cpp (GPL-3.0-only,
//     adapted from noproto/FlipperMfkey) — the single-sample enumeration
//     whose math recovered sector 1 on the lab card. Its filter/contribution/
//     extend/rollback/toKey logic is carried over verbatim; what changes is
//     the memory layout and the API.
//
// Bruce is AGPL-3.0, so this file and the work that links it are distributed
// as AGPL-3.0 (GPL-3.0 section 13 permits the combination).
//
// Distributed WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
//
// Memory design note. Flipper's MFKey app allocates its tables as many small
// fixed blocks, not one big block, and that shape is the part that survives a
// fragmented heap. Their full-speed layout is 2x16x2312 B + 2x5120 B + 4096 B
// (~88 KiB, mfkey.c:170); their half-speed layout uses 8 buckets instead of 16
// (2x8x2312 B + 2x5120 B + 4096 B, ~58 KiB, mfkey.c:171-172). This port uses
// their half-speed bucket count and their per-bucket allocation shape:
// 16 bucket blocks of 2,688 B and 2 work blocks of 5,120 B, for 53,248 B total
// with no single block over 5,120 B. Bucket states are packed into 24 bits
// (mfkey.h:16-23) and sorting is in place (in-place heapsort plus a merge walk
// over the two expanded halves), so no radix-sort table is needed.
#include "mfc_flipper.h"

#include "crypto1.h"

#include <cstdlib>
#include <cstring>

#if defined(MFC_FLIPPER_TESTING)
// Provided by the host test: a counting allocator, so peak scratch and the
// largest single allocation are measured rather than claimed.
void *mfc_flipper_test_allocate(size_t bytes);
void mfc_flipper_test_release(void *allocation);
#endif

namespace mfc_flipper {
namespace {

constexpr uint32_t kOddPoly = 0x29ce5cu;
constexpr uint32_t kEvenPoly = 0x870804u;

// 8 MSB buckets per sweep (upstream half-speed MSB_LIMIT), 896 packed
// candidates per bucket and per side (upstream MSB_BUCKET_CAPACITY is 768),
// 1280 expanded states per side. Measured worst case on random samples: 563
// candidates per bucket and 767 after the three-bit expansion, so both caps
// keep >1.5x headroom.
constexpr unsigned kBand = 8;
constexpr unsigned kBucketCapacity = 896;
constexpr unsigned kWorkCapacity = 1280;
constexpr unsigned kCandidateBytes = 3; // 24 low bits; the MSB is the bucket

constexpr size_t kBucketBytes = kBucketCapacity * kCandidateBytes; // 2,688
constexpr size_t kWorkBytes = kWorkCapacity * sizeof(uint32_t);    // 5,120
constexpr size_t kScratchTotal = 2 * kBand * kBucketBytes + 2 * kWorkBytes;

static_assert(kScratchTotal <= 61440, "Total scratch must stay within 60 KiB");
static_assert(kBucketBytes <= 16384 && kWorkBytes <= 16384,
              "No single allocation may exceed 16 KiB");

void *allocateBlock(size_t bytes) {
#if defined(MFC_FLIPPER_TESTING)
    return mfc_flipper_test_allocate(bytes);
#else
    return std::malloc(bytes);
#endif
}

void releaseBlock(void *allocation) {
#if defined(MFC_FLIPPER_TESTING)
    mfc_flipper_test_release(allocation);
#else
    std::free(allocation);
#endif
}

// Small fixed blocks, freed on every exit path. Only the pointers and the
// candidate counts live on the stack.
struct Scratch {
    uint8_t *buckets[2][kBand];
    uint16_t counts[2][kBand];
    uint32_t *work[2];

    bool allocate() {
        for (unsigned side = 0; side < 2; ++side) {
            work[side] = nullptr;
            for (unsigned b = 0; b < kBand; ++b) {
                buckets[side][b] = nullptr;
                counts[side][b] = 0;
            }
        }
        for (unsigned side = 0; side < 2; ++side) {
            work[side] = static_cast<uint32_t *>(allocateBlock(kWorkBytes));
            if (!work[side]) {
                release();
                return false;
            }
            for (unsigned b = 0; b < kBand; ++b) {
                buckets[side][b] = static_cast<uint8_t *>(allocateBlock(kBucketBytes));
                if (!buckets[side][b]) {
                    release();
                    return false;
                }
            }
        }
        return true;
    }

    void release() {
        for (unsigned side = 0; side < 2; ++side) {
            for (unsigned b = 0; b < kBand; ++b) {
                if (buckets[side][b]) releaseBlock(buckets[side][b]);
                buckets[side][b] = nullptr;
            }
            if (work[side]) releaseBlock(work[side]);
            work[side] = nullptr;
        }
    }
};

enum class Step { Continue, Stop, Overflow, Cancelled };

uint32_t parity(uint32_t x) {
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    return (0x6996u >> (x & 15u)) & 1u;
}

// Crypto1 filter; kept inline because it is called millions of times and a
// lookup table would not fit the budget.
uint32_t filter(uint32_t x) {
    uint32_t f = (0xf22c0u >> (x & 15u)) & 16u;
    f |= (0x6c9c0u >> ((x >> 4) & 15u)) & 8u;
    f |= (0x3c8b0u >> ((x >> 8) & 15u)) & 4u;
    f |= (0x1e458u >> ((x >> 12) & 15u)) & 2u;
    f |= (0x0d938u >> ((x >> 16) & 15u)) & 1u;
    return (0xec57e80au >> f) & 1u;
}

uint32_t contribution(uint32_t x, uint32_t m1, uint32_t m2, uint32_t input) {
    uint32_t p = ((x >> 25) << 1) | parity(x & m1);
    p = (p << 1) | parity(x & m2);
    return ((p << 24) | (x & 0xffffffu)) ^ (input << 24);
}

inline uint32_t candidateGet(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}
inline void candidatePut(uint8_t *p, uint32_t value24) {
    p[0] = (uint8_t)value24;
    p[1] = (uint8_t)(value24 >> 8);
    p[2] = (uint8_t)(value24 >> 16);
}

bool insertUnique(uint8_t *data, uint16_t &count, uint32_t value24) {
    for (uint16_t i = 0; i < count; ++i)
        if (candidateGet(data + (size_t)i * kCandidateBytes) == value24) return true;
    if (count >= kBucketCapacity) return false;
    candidatePut(data + (size_t)count * kCandidateBytes, value24);
    ++count;
    return true;
}

struct Control {
    Progress callback;
    void *context;
    unsigned done = 0;
    unsigned steps = 0;
    unsigned emitted = 0;
    Control(Progress cb, void *ctx) : callback(cb), context(ctx) {}
    bool poll() const { return !callback || callback(done, 256, context); }
    // Bounds work between callbacks outside the semi-state sweep.
    bool tick() {
        if (++steps < 4096) return true;
        steps = 0;
        return poll();
    }
    // Cancellation is checked after every emitted candidate, so a cancelled
    // search never calls the sink again.
    bool candidateEmitted() {
        ++emitted;
        return poll();
    }
};

// Twelve rounds from one 20-bit semi-state. The first four rounds consume
// filter bits, the next eight fold in the contribution. Depth-first with at
// most one pending sibling per depth (13 entries), as upstream does with a
// growing array.
Step enumerate12(uint32_t semi, uint32_t ks, unsigned side, unsigned base, uint32_t input,
                 Scratch &scratch) {
    struct Node {
        uint32_t state;
        unsigned round;
    } pending[13];
    unsigned size = 1;
    pending[0] = {semi, 1};
    const uint32_t m1 = side ? kOddPoly : (kEvenPoly << 1) | 1u;
    const uint32_t m2 = side ? (kEvenPoly << 1) | 1u : kOddPoly << 1;
    while (size) {
        const Node node = pending[--size];
        const uint32_t shifted = node.state << 1;
        const uint32_t bit = (ks >> node.round) & 1u;
        for (uint32_t b = 0; b != 2; ++b) {
            uint32_t value = shifted | b;
            if (filter(value) != bit) continue;
            if (node.round > 4) {
                const uint32_t in = side ? (input >> (2 * (node.round - 4))) & 3u : 0;
                value = contribution(value, m1, m2, in);
            }
            if (node.round == 12) {
                const unsigned bucket = value >> 24;
                if (bucket >= base && bucket < base + kBand &&
                    !insertUnique(scratch.buckets[side][bucket - base],
                                  scratch.counts[side][bucket - base], value & 0xffffffu))
                    return Step::Overflow;
            } else {
                if (size >= 13) return Step::Overflow;
                pending[size++] = {value, node.round + 1};
            }
        }
    }
    return Step::Continue;
}

// One expansion round over a table. A split moves the next unprocessed entry
// to the end instead of dropping it.
Step extend(uint32_t *data, unsigned &count, uint32_t bit, uint32_t m1, uint32_t m2,
            uint32_t input, Control &control) {
    unsigned i = 0;
    while (i < count) {
        if (!control.tick()) return Step::Cancelled;
        const uint32_t x = data[i] << 1;
        const uint32_t f0 = filter(x), f1 = filter(x | 1u);
        if (f0 != f1) {
            data[i++] = contribution(x | (f0 ^ bit), m1, m2, input);
        } else if (f0 == bit) {
            if (count >= kWorkCapacity) return Step::Overflow;
            if (i + 1 < count) data[count] = data[i + 1];
            ++count;
            data[i++] = contribution(x, m1, m2, input);
            data[i++] = contribution(x | 1u, m1, m2, input);
        } else {
            data[i] = data[--count];
        }
    }
    return Step::Continue;
}

void swap32(uint32_t &a, uint32_t &b) {
    const uint32_t t = a;
    a = b;
    b = t;
}
void sift(uint32_t *a, unsigned root, unsigned count) {
    while (root < count / 2) {
        unsigned child = root * 2 + 1;
        if (child + 1 < count && a[child] < a[child + 1]) ++child;
        if (a[root] >= a[child]) return;
        swap32(a[root], a[child]);
        root = child;
    }
}
// In-place heapsort: no scratch table, no recursion.
void sort(uint32_t *a, unsigned count) {
    for (unsigned i = count / 2; i; --i) sift(a, i - 1, count);
    for (unsigned n = count; n > 1; --n) {
        swap32(a[0], a[n - 1]);
        sift(a, 0, n - 1);
    }
}

void rollback(Crypto1State &s, uint32_t input) {
    for (int i = 31; i >= 0; --i) {
        s.odd &= 0xffffffu;
        swap32(s.odd, s.even);
        uint32_t feedback = s.even & 1u;
        s.even >>= 1;
        feedback ^= s.even & kEvenPoly;
        feedback ^= s.odd & kOddPoly;
        feedback ^= (input >> (i ^ 24)) & 1u;
        s.even |= parity(feedback) << 23;
    }
}

void toKey(const Crypto1State &state, uint8_t key[6]) {
    uint64_t value = 0;
    for (int i = 23; i >= 0; --i) {
        value = (value << 1) | ((state.odd >> (i ^ 3)) & 1u);
        value = (value << 1) | ((state.even >> (i ^ 3)) & 1u);
    }
    for (unsigned i = 0; i < 6; ++i) key[i] = uint8_t(value >> ((5 - i) * 8));
}

uint8_t oddParityBit(uint8_t b) {
    b ^= b >> 4;
    b ^= b >> 2;
    b ^= b >> 1;
    return (uint8_t)((b & 1u) ^ 1u);
}

// Same bit order as crypto1_word, but also reports the keystream bit riding on
// each of the first three transmitted parity bits.
uint32_t wordWithParity(Crypto1State *s, uint32_t in, uint8_t par[3]) {
    uint32_t ret = 0;
    for (int i = 0; i < 32; i++) {
        ret |= (uint32_t)crypto1_bit(s, (uint8_t)((in >> (24 ^ i)) & 1u), 0) << (24 ^ i);
        if ((i & 7) == 7 && i < 24) par[i >> 3] = crypto1_filter_bit(s);
    }
    return ret;
}

// Keystream window check plus the three parity bits, then the key.
bool verify(const Crypto1State &state, const Sample &sample, uint8_t key[6]) {
    Crypto1State rolled = state;
    rollback(rolled, sample.uid ^ sample.nt);
    Crypto1State probe = rolled;
    uint8_t par[3] = {0, 0, 0};
    if (wordWithParity(&probe, sample.uid ^ sample.nt, par) != (sample.nt ^ sample.ntEnc))
        return false;
    for (int i = 0; i < 3; i++) {
        const uint8_t byte = (uint8_t)(sample.nt >> (24 - 8 * i));
        if ((uint8_t)(par[i] ^ oddParityBit(byte)) != (uint8_t)((sample.parBits >> i) & 1u))
            return false;
    }
    toKey(rolled, key);
    return true;
}

struct Sink {
    CandidateSink sink = nullptr;
    void *context = nullptr;
};

// Expand one bucket band of both halves by the three remaining filter bits,
// then walk the two sorted tables on equal MSB.
Step join(Scratch &scratch, unsigned bucket, uint32_t oks, uint32_t eks, uint32_t input,
          const Sample &sample, const Sink &sink, uint8_t key[6], Control &control) {
    unsigned counts[2] = {scratch.counts[0][bucket], scratch.counts[1][bucket]};
    for (unsigned side = 0; side < 2; ++side) {
        for (unsigned i = 0; i < counts[side]; ++i)
            scratch.work[side][i] =
                candidateGet(scratch.buckets[side][bucket] + (size_t)i * kCandidateBytes) |
                ((uint32_t)bucket << 24);
    }
    // The MSBs already match; only three filter bits per half remain.
    for (unsigned round = 13; round <= 15; ++round) {
        input >>= 2;
        Step step = extend(scratch.work[0], counts[0], (oks >> round) & 1u,
                           (kEvenPoly << 1) | 1u, kOddPoly << 1, 0, control);
        if (step != Step::Continue) return step;
        step = extend(scratch.work[1], counts[1], (eks >> round) & 1u, kOddPoly,
                      (kEvenPoly << 1) | 1u, input & 3u, control);
        if (step != Step::Continue) return step;
    }
    for (unsigned side = 0; side < 2; ++side) sort(scratch.work[side], counts[side]);
    unsigned o = 0, e = 0;
    while (o < counts[0] && e < counts[1]) {
        const unsigned om = scratch.work[0][o] >> 24, em = scratch.work[1][e] >> 24;
        if (om < em) {
            ++o;
            continue;
        }
        if (em < om) {
            ++e;
            continue;
        }
        unsigned oe = o + 1, ee = e + 1;
        while (oe < counts[0] && (scratch.work[0][oe] >> 24) == om) ++oe;
        while (ee < counts[1] && (scratch.work[1][ee] >> 24) == em) ++ee;
        for (unsigned j = e; j < ee; ++j) {
            const uint32_t ev = scratch.work[1][j];
            const uint32_t advanced = (ev << 1) ^ parity(ev & kEvenPoly) ^ ((input >> 2) & 1u);
            for (unsigned i = o; i < oe; ++i) {
                if (!control.tick()) return Step::Cancelled;
                const uint32_t od = scratch.work[0][i];
                const Crypto1State state{advanced ^ parity(od & kOddPoly), od};
                if (!verify(state, sample, key)) continue;
                if (sink.sink(key, sink.context)) return Step::Stop;
                if (!control.candidateEmitted()) return Step::Cancelled;
            }
        }
        o = oe;
        e = ee;
    }
    return Step::Continue;
}

Result search(Scratch &scratch, const Sample &sample, const Sink &sink, uint8_t key[6],
              Control &control) {
    const uint32_t ks = sample.nt ^ sample.ntEnc;
    uint32_t oks = 0, eks = 0;
    for (int i = 31; i >= 1; i -= 2) oks = (oks << 1) | ((ks >> (i ^ 24)) & 1u);
    for (int i = 30; i >= 0; i -= 2) eks = (eks << 1) | ((ks >> (i ^ 24)) & 1u);
    const uint32_t in = sample.uid ^ sample.nt;
    const uint32_t input = ((in >> 16 & 0xffu) | (in << 16) | (in & 0xff00u)) << 1;
    for (unsigned base = 0; base < 256; base += kBand) {
        std::memset(scratch.counts, 0, sizeof(scratch.counts));
        // Exactly 2^20 semi-states, as upstream: 2^20 itself is excluded.
        for (uint32_t semi = 0; semi < (1u << 20); ++semi) {
            if ((semi & 4095u) == 0 && !control.poll()) return Result::Cancelled;
            const uint32_t f = filter(semi);
            for (unsigned side = 0; side < 2; ++side) {
                const uint32_t half = side ? eks : oks;
                if (f != (half & 1u)) continue;
                const Step step = enumerate12(semi, half, side, base, input, scratch);
                if (step == Step::Overflow) return Result::NoMemory;
                if (step != Step::Continue) return Result::Cancelled;
            }
        }
        for (unsigned bucket = 0; bucket < kBand; ++bucket) {
            if (!control.poll()) return Result::Cancelled;
            const Step step =
                join(scratch, bucket, oks, eks, input >> 16, sample, sink, key, control);
            if (step == Step::Stop) return Result::Ok;
            if (step == Step::Overflow) return Result::NoMemory;
            if (step != Step::Continue) return Result::Cancelled;
            ++control.done;
        }
    }
    return control.poll() ? Result::Ok : Result::Cancelled;
}

} // namespace

size_t scratchBytes() { return kScratchTotal; }

size_t maxAllocationBytes() { return kWorkBytes > kBucketBytes ? kWorkBytes : kBucketBytes; }

Result enumerateKeys(const Sample &s, CandidateSink sink, void *ctx, Progress progress,
                     void *progressContext) {
    if (!sink || s.parBits > 7) return Result::InvalidInput;
    Control control{progress, progressContext};
    if (!control.poll()) return Result::Cancelled;
    Scratch scratch;
    if (!scratch.allocate()) return Result::NoMemory;
    const Sink target{sink, ctx};
    uint8_t candidate[6];
    const Result result = search(scratch, s, target, candidate, control);
    scratch.release();
    if (result == Result::Ok && !control.emitted) return Result::NoCandidates;
    return result;
}

} // namespace mfc_flipper
