// SPDX-License-Identifier: GPL-3.0-only
// Adapted from noproto/FlipperMfkey dev/ndv.c and fap_plugin/mfkey.c,
// revision 9928b2ee117f0ed6e5e202f7c06f8ce5797382fa (noproto, AG, ALiberty).
// Modified 2026-10-25: portable nested-only core, bounded storage, unsigned
// arithmetic, checked extensions, iterative traversal/join, cancellation.
// Distributed WITHOUT ANY WARRANTY. See docs/MFC_RECOVERY_LICENSE.md.
#include "mfc_recovery.h"
#include "crypto1.h"
#include <cstdlib>
#include <cstring>

#if defined(ESP32)
#include <esp_heap_caps.h>
#endif

namespace mfc_recovery {
namespace {
constexpr uint32_t OddPoly = 0x29ce5cu, EvenPoly = 0x870804u;
constexpr unsigned Batch = 8, BucketCapacity = 1024, WorkCapacity = 4096;
struct Scratch {
    uint32_t buckets[2][Batch][BucketCapacity];
    unsigned counts[2][Batch];
    uint32_t work[2][WorkCapacity];
};
static_assert(sizeof(Scratch) == 98368, "Review scratch memory budget");
static_assert(sizeof(Scratch) < 100 * 1024, "Scratch exceeds 100 KiB");

uint32_t parity(uint32_t x) {
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    return (0x6996u >> (x & 15u)) & 1u;
}
// Kept inline here: millions of filter calls, without a megabyte lookup table.
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

struct Control {
    Progress callback;
    void *context;
    unsigned completed = 0;
    unsigned work = 0;
    Control(Progress cb, void *ctx) : callback(cb), context(ctx) {}
    bool poll() const { return !callback || callback(completed, 256, context); }
    bool tick() { // Also bound work between callbacks outside semi-state enumeration.
        if (++work < 4096) return true;
        work = 0;
        return poll();
    }
};

bool insert_unique(uint32_t *data, unsigned &count, unsigned capacity, uint32_t value) {
    for (unsigned i = 0; i < count; ++i)
        if (data[i] == value) return true;
    if (count >= capacity) return false;
    data[count++] = value;
    return true;
}

// Upstream state_loop's twelve rounds, depth-first rather than a growing array.
// At most one pending sibling per depth: 13 entries suffice even if all bits branch.
// The first four rounds extend filter bits; the next eight build contribution MSBs.
Result enumerate(uint32_t semi, uint32_t ks, unsigned side, unsigned base,
                 uint32_t input, Scratch &scratch) {
    struct Node { uint32_t state; unsigned round; } pending[13];
    unsigned size = 1;
    pending[0] = {semi, 1};
    const uint32_t m1 = side ? OddPoly : (EvenPoly << 1) | 1u;
    const uint32_t m2 = side ? (EvenPoly << 1) | 1u : OddPoly << 1;
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
                if (bucket >= base && bucket < base + Batch &&
                    !insert_unique(scratch.buckets[side][bucket - base],
                                   scratch.counts[side][bucket - base], BucketCapacity, value))
                    return Result::Overflow;
            } else {
                if (size >= 13) return Result::Overflow;
                pending[size++] = {value, node.round + 1};
            }
        }
    }
    return Result::NotFound;
}

// Counts, not inclusive tails. A split displaces the next unprocessed element
// to the end, except at the last element (where upstream read past the end).
Result extend(uint32_t *data, unsigned &count, unsigned capacity, uint32_t bit,
              uint32_t m1, uint32_t m2, uint32_t input, Control &control) {
    unsigned i = 0;
    while (i < count) {
        if (!control.tick()) return Result::Cancelled;
        const uint32_t x = data[i] << 1;
        const uint32_t f0 = filter(x), f1 = filter(x | 1u);
        if (f0 != f1) {
            data[i++] = contribution(x | (f0 ^ bit), m1, m2, input);
        } else if (f0 == bit) {
            if (count >= capacity) return Result::Overflow;
            if (i + 1 < count) data[count] = data[i + 1];
            ++count;
            data[i++] = contribution(x, m1, m2, input);
            data[i++] = contribution(x | 1u, m1, m2, input);
        } else {
            data[i] = data[--count];
        }
    }
    return Result::NotFound;
}

void swap(uint32_t &a, uint32_t &b) { const uint32_t t = a; a = b; b = t; }
void sift(uint32_t *a, unsigned root, unsigned count) {
    while (root < count / 2) {
        unsigned child = root * 2 + 1;
        if (child + 1 < count && a[child] < a[child + 1]) ++child;
        if (a[root] >= a[child]) return;
        swap(a[root], a[child]);
        root = child;
    }
}
// Iterative heapsort: no library-dependent allocations or recursive stack depth.
void sort(uint32_t *a, unsigned count) {
    for (unsigned i = count / 2; i; --i) sift(a, i - 1, count);
    for (unsigned n = count; n > 1; --n) {
        swap(a[0], a[n - 1]);
        sift(a, 0, n - 1);
    }
}

void rollback(Crypto1State &s, uint32_t input) {
    for (int i = 31; i >= 0; --i) {
        s.odd &= 0xffffffu;
        swap(s.odd, s.even);
        uint32_t feedback = s.even & 1u;
        s.even >>= 1;
        feedback ^= s.even & EvenPoly;
        feedback ^= s.odd & OddPoly;
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

bool verify(Crypto1State state, uint32_t uid, const Sample &first, const Sample &second,
            uint8_t key[6]) {
    rollback(state, uid ^ second.nt);
    Crypto1State a = state, b = state;
    if (crypto1_word(&a, uid ^ first.nt, 0) != (first.nt ^ first.encrypted) ||
        crypto1_word(&b, uid ^ second.nt, 0) != (second.nt ^ second.encrypted)) return false;
    toKey(state, key);
    return true;
}

// Which sample the search is built around, and how a hit is reported.
// `first == nullptr` selects static-nonce mode: one sample only, every
// consistent key goes to `sink`.
struct Target {
    const Sample *first = nullptr;
    const Sample *second = nullptr;
    int parity = -1; // -1 = ignore the transmitted parity bits
    CandidateSink sink = nullptr;
    void *context = nullptr;
};

uint8_t oddParityBit(uint8_t b) {
    b ^= b >> 4;
    b ^= b >> 2;
    b ^= b >> 1;
    return (uint8_t)((b & 1u) ^ 1u);
}

// Same bit order as crypto1_word, but also returns the keystream bit that
// rides on each of the first three transmitted parity bits.
uint32_t wordWithParity(Crypto1State *s, uint32_t in, uint8_t par[3]) {
    uint32_t ret = 0;
    for (int i = 0; i < 32; i++) {
        ret |= (uint32_t)crypto1_bit(s, (uint8_t)((in >> (24 ^ i)) & 1u), 0) << (24 ^ i);
        if ((i & 7) == 7 && i < 24) par[i >> 3] = crypto1_filter_bit(s);
    }
    return ret;
}

bool verifyOne(Crypto1State state, uint32_t uid, const Target &t, uint8_t key[6]) {
    const Sample &sample = *t.second;
    rollback(state, uid ^ sample.nt);
    Crypto1State k = state, b = state;
    uint8_t par[3] = {0, 0, 0};
    if (wordWithParity(&b, uid ^ sample.nt, par) != (sample.nt ^ sample.encrypted)) return false;
    if (t.parity >= 0) {
        for (int i = 0; i < 3; i++) {
            const uint8_t byte = (uint8_t)(sample.nt >> (24 - 8 * i));
            if ((uint8_t)(par[i] ^ oddParityBit(byte)) != (uint8_t)((t.parity >> i) & 1u))
                return false;
        }
    }
    toKey(k, key);
    return t.sink ? t.sink(key, t.context) : true;
}

Result join(Scratch &scratch, unsigned bucket, uint32_t oks, uint32_t eks, uint32_t input,
            uint32_t uid, const Target &t, uint8_t key[6], Control &control) {
    unsigned counts[2] = {scratch.counts[0][bucket], scratch.counts[1][bucket]};
    for (unsigned side = 0; side < 2; ++side) {
        if (counts[side] > WorkCapacity) return Result::Overflow;
        std::memcpy(scratch.work[side], scratch.buckets[side][bucket], counts[side] * sizeof(uint32_t));
    }
    // The initial MSBs already match. Only three filter bits per half remain.
    // This specializes upstream old_recover(rem=3) without recursion.
    for (unsigned round = 13; round <= 15; ++round) {
        input >>= 2;
        Result r = extend(scratch.work[0], counts[0], WorkCapacity, (oks >> round) & 1u,
                          (EvenPoly << 1) | 1u, OddPoly << 1, 0, control);
        if (r != Result::NotFound) return r;
        r = extend(scratch.work[1], counts[1], WorkCapacity, (eks >> round) & 1u,
                   OddPoly, (EvenPoly << 1) | 1u, input & 3u, control);
        if (r != Result::NotFound) return r;
    }
    for (unsigned side = 0; side < 2; ++side) sort(scratch.work[side], counts[side]);
    unsigned o = 0, e = 0;
    while (o < counts[0] && e < counts[1]) {
        const unsigned om = scratch.work[0][o] >> 24, em = scratch.work[1][e] >> 24;
        if (om < em) { ++o; continue; }
        if (em < om) { ++e; continue; }
        unsigned oe = o + 1, ee = e + 1;
        while (oe < counts[0] && (scratch.work[0][oe] >> 24) == om) ++oe;
        while (ee < counts[1] && (scratch.work[1][ee] >> 24) == em) ++ee;
        for (unsigned j = e; j < ee; ++j) {
            const uint32_t ev = scratch.work[1][j];
            const uint32_t advanced = (ev << 1) ^ parity(ev & EvenPoly) ^ ((input >> 2) & 1u);
            for (unsigned i = o; i < oe; ++i) {
                if (!control.tick()) return Result::Cancelled;
                const uint32_t od = scratch.work[0][i];
                Crypto1State state{advanced ^ parity(od & OddPoly), od};
                if (t.first ? verify(state, uid, *t.first, *t.second, key)
                            : verifyOne(state, uid, t, key)) return Result::Found;
            }
        }
        o = oe;
        e = ee;
    }
    return Result::NotFound;
}

Result search(Scratch &scratch, uint32_t uid, const Target &t, uint8_t key[6], Control &control) {
    const Sample &second = *t.second;
    const uint32_t ks = second.nt ^ second.encrypted;
    uint32_t oks = 0, eks = 0;
    for (int i = 31; i >= 1; i -= 2) oks = (oks << 1) | ((ks >> (i ^ 24)) & 1u);
    for (int i = 30; i >= 0; i -= 2) eks = (eks << 1) | ((ks >> (i ^ 24)) & 1u);
    const uint32_t in = uid ^ second.nt;
    const uint32_t input = ((in >> 16 & 0xffu) | (in << 16) | (in & 0xff00u)) << 1;
    for (unsigned base = 0; base < 256; base += Batch) {
        std::memset(scratch.counts, 0, sizeof(scratch.counts));
        // Exactly 2^20 initial filter inputs; upstream included 2^20 itself.
        for (uint32_t semi = 0; semi < (1u << 20); ++semi) {
            if ((semi & 4095u) == 0 && !control.poll()) return Result::Cancelled;
            const uint32_t f = filter(semi);
            for (unsigned side = 0; side < 2; ++side) {
                const uint32_t half = side ? eks : oks;
                if (f != (half & 1u)) continue;
                const Result r = enumerate(semi, half, side, base, input, scratch);
                if (r != Result::NotFound) return r;
            }
        }
        for (unsigned bucket = 0; bucket < Batch; ++bucket) {
            if (!control.poll()) return Result::Cancelled;
            const Result r = join(scratch, bucket, oks, eks, input >> 16, uid, t, key, control);
            if (r != Result::NotFound) return r;
            ++control.completed;
        }
    }
    return control.poll() ? Result::NotFound : Result::Cancelled;
}
} // namespace

#if defined(ESP32)
// Prefer internal RAM for solver speed; fall back to PSRAM when the 98 KiB
// scratch block would otherwise fail on a fragmented heap.
static void *alloc_scratch(size_t size) {
    void *p = heap_caps_malloc(size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!p) p = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    return p;
}
static void free_scratch(void *p) { heap_caps_free(p); }
#else
static void *alloc_scratch(size_t size) { return std::malloc(size); }
static void free_scratch(void *p) { std::free(p); }
#endif

Result recover(uint32_t uid, const Sample &first, const Sample &second, uint8_t key[6],
               Progress progress, void *context) {
    if (!key || first.nt == second.nt) return Result::InvalidInput;
    Control control{progress, context};
    if (!control.poll()) return Result::Cancelled;
#ifdef MFC_RECOVERY_TESTING
    // Test-only allocator fault injection / accounting; search is unchanged.
    Scratch *scratch = static_cast<Scratch *>(test_allocate(sizeof(Scratch)));
#else
    Scratch *scratch = static_cast<Scratch *>(alloc_scratch(sizeof(Scratch)));
#endif
    if (!scratch) return Result::NoMemory;
    uint8_t candidate[6];
    Target target{&first, &second, -1, nullptr, nullptr};
    const Result result = search(*scratch, uid, target, candidate, control);
#ifdef MFC_RECOVERY_TESTING
    test_release(scratch);
#else
    free_scratch(scratch);
#endif
    if (result == Result::Found) std::memcpy(key, candidate, sizeof(candidate));
    return result;
}

Result enumerateKeys(uint32_t uid, const Sample &sample, int parity, CandidateSink sink,
                     void *context, Progress progress, void *progressContext) {
    if (!sink) return Result::InvalidInput;
    Control control{progress, progressContext};
    if (!control.poll()) return Result::Cancelled;
    Scratch *scratch = static_cast<Scratch *>(alloc_scratch(sizeof(Scratch)));
    if (!scratch) return Result::NoMemory;
    uint8_t candidate[6];
    Target target{nullptr, &sample, parity, sink, context};
    const Result result = search(*scratch, uid, target, candidate, control);
    free_scratch(scratch);
    return result;
}
} // namespace mfc_recovery
