// Host tests for the low-memory MIFARE Classic key enumeration (mfc_flipper).
//
// Licence: AGPL-3.0-or-later. The solver under test is a port of
// flipperdevices/flipperzero-good-faps mfkey (GPL-3.0) onto the enumeration in
// src/modules/rfid/mfc_recovery.cpp (GPL-3.0-only), which this test also uses
// as an equivalence oracle. See mfc_flipper.h for the full attribution.
//
// These are the Phase 1 gate: they prove (a) the true key is always offered for
// synthetic samples, (b) the real static-nonce hardware sample is covered,
// (c) peak scratch and the largest single allocation are measured and within
// budget, (d) the search is deterministic, and (e) cancellation stops the sink
// immediately.
//
// Every key in this file is synthetic. The only real hardware constants are the
// sample window (uid/nt/keystream/parity), which contains no key material.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

#include "crypto1.h"
#include "mfc_flipper.h"
#include "mfc_recovery.h" // oracle: the hardware-proven implementation in this repo

// ---------------------------------------------------------------------------
// Counting allocator. The solver asks for its single scratch block through
// this hook, so the peak is measured, not estimated.
// ---------------------------------------------------------------------------
namespace {
std::atomic<size_t> gLive{0};
std::atomic<size_t> gPeak{0};
std::atomic<size_t> gMaxAlloc{0};
std::atomic<unsigned> gAllocations{0};
std::atomic<unsigned> gGlobalNewCalls{0};

struct BlockHeader {
    size_t bytes;
};

void notePeak(size_t live) {
    size_t prev = gPeak.load(std::memory_order_relaxed);
    while (live > prev && !gPeak.compare_exchange_weak(prev, live, std::memory_order_relaxed)) {
    }
}

void noteAllocation(size_t bytes) {
    size_t prev = gMaxAlloc.load(std::memory_order_relaxed);
    while (bytes > prev && !gMaxAlloc.compare_exchange_weak(prev, bytes, std::memory_order_relaxed)) {
    }
}
} // namespace

void *mfc_flipper_test_allocate(size_t bytes) {
    BlockHeader *header = static_cast<BlockHeader *>(std::malloc(bytes + sizeof(BlockHeader)));
    if (!header) return nullptr;
    header->bytes = bytes;
    ++gAllocations;
    noteAllocation(bytes);
    notePeak(gLive.fetch_add(bytes) + bytes);
    return header + 1;
}

void mfc_flipper_test_release(void *allocation) {
    if (!allocation) return;
    BlockHeader *header = static_cast<BlockHeader *>(allocation) - 1;
    gLive.fetch_sub(header->bytes);
    std::free(header);
}

// Any C++ allocation made by the solver would show up here. The test's own
// vectors are allocated before/after the measured window, so a non-zero delta
// inside the window means the solver allocated behind the scratch block.
void *operator new(size_t bytes) {
    ++gGlobalNewCalls;
    void *p = std::malloc(bytes ? bytes : 1);
    if (!p) throw std::bad_alloc();
    return p;
}
void operator delete(void *p) noexcept { std::free(p); }
void operator delete(void *p, size_t) noexcept { std::free(p); }
void *operator new[](size_t bytes) { return operator new(bytes); }
void operator delete[](void *p) noexcept { std::free(p); }
void operator delete[](void *p, size_t) noexcept { std::free(p); }

namespace {

constexpr size_t kScratchBudget = 61440;
constexpr size_t kMaxAllocationBudget = 16384;

uint64_t pack(const uint8_t key[6]) {
    uint64_t v = 0;
    for (int i = 0; i < 6; i++) v = (v << 8) | key[i];
    return v;
}

struct Vector {
    uint32_t uid;
    uint32_t nt;
    uint64_t key;
};

// The caller's job on hardware: run one authentication and log the window.
mfc_flipper::Sample sampleFor(const Vector &v) {
    Crypto1State s;
    crypto1_init(&s, v.key);
    const uint32_t ks = crypto1_word(&s, v.nt ^ v.uid, 0);
    uint8_t par[3];
    for (int i = 0; i < 3; i++) {
        const uint8_t byte = (uint8_t)(v.nt >> (24 - 8 * i));
        const uint8_t ksBit = (uint8_t)((ks >> (24 ^ (8 * i + 8))) & 1u);
        par[i] = (uint8_t)(ksBit ^ nfc_oddparity(byte));
    }
    mfc_flipper::Sample out;
    out.uid = v.uid;
    out.nt = v.nt;
    out.ntEnc = v.nt ^ ks;
    out.parBits = (uint8_t)(par[0] | (par[1] << 1) | (par[2] << 2));
    return out;
}

struct CollectCtx {
    std::vector<uint64_t> keys;
    bool present = false;
    uint64_t want = 0;
};

struct OracleCtx {
    std::vector<uint64_t> keys;
};

bool oracleSink(const uint8_t key[6], void *ctx) {
    static_cast<OracleCtx *>(ctx)->keys.push_back(pack(key));
    return false;
}

// Faithfulness oracle: run the same sample through the hardware-proven
// implementation (98 KiB scratch, 8-bucket bands). The memory-reduced port must
// emit the identical candidate sequence, otherwise the packing/band changes
// silently altered the math.
bool equivalentToProvenSolver(const mfc_flipper::Sample &s, const std::vector<uint64_t> &mine,
                              const char *name) {
    mfc_recovery::Sample oracleSample;
    oracleSample.nt = s.nt;
    oracleSample.encrypted = s.ntEnc;
    OracleCtx oracle;
    const mfc_recovery::Result r =
        mfc_recovery::enumerateKeys(s.uid, oracleSample, s.parBits, oracleSink, &oracle);
    const bool same = r == mfc_recovery::Result::NotFound && oracle.keys == mine;
    printf("%s: proven_oracle_candidates=%zu identical_sequence=%d\n", name, oracle.keys.size(),
           same ? 1 : 0);
    return same;
}

bool collectSink(const uint8_t key[6], void *ctx) {
    CollectCtx *c = static_cast<CollectCtx *>(ctx);
    const uint64_t v = pack(key);
    c->keys.push_back(v);
    if (v == c->want) c->present = true;
    return false;
}

struct AcceptCtx {
    uint64_t want = 0;
    uint8_t got[6] = {0};
    unsigned calls = 0;
};

bool acceptSink(const uint8_t key[6], void *ctx) {
    AcceptCtx *c = static_cast<AcceptCtx *>(ctx);
    ++c->calls;
    if (pack(key) != c->want) return false;
    std::memcpy(c->got, key, 6);
    return true;
}

// Independent re-check of a candidate against the sample, using Crypto1
// directly instead of trusting the solver's own filter.
bool reproducesWindow(const uint8_t key[6], const mfc_flipper::Sample &s) {
    uint64_t k = 0;
    for (int i = 0; i < 6; i++) k = (k << 8) | key[i];
    Crypto1State st;
    crypto1_init(&st, k);
    const uint32_t ks = crypto1_word(&st, s.nt ^ s.uid, 0);
    if (ks != (s.nt ^ s.ntEnc)) return false;
    // Parity bits ride on the same stream; clock the word again from a fresh
    // state while sampling the filter after each of the first three bytes.
    crypto1_init(&st, k);
    uint8_t par[3] = {0, 0, 0};
    for (int i = 0; i < 32; i++) {
        crypto1_bit(&st, (uint8_t)(((s.nt ^ s.uid) >> (24 ^ i)) & 1u), 0);
        if ((i & 7) == 7 && i < 24) par[i >> 3] = crypto1_filter_bit(&st);
    }
    for (int i = 0; i < 3; i++) {
        const uint8_t byte = (uint8_t)(s.nt >> (24 - 8 * i));
        if ((uint8_t)(par[i] ^ nfc_oddparity(byte)) != (uint8_t)((s.parBits >> i) & 1u))
            return false;
    }
    return true;
}

int gFailures = 0;

void check(bool ok, const char *what) {
    if (!ok) {
        ++gFailures;
        printf("  check failed: %s\n", what);
    }
}

struct MemoryReport {
    size_t peak = 0;
    size_t maxAlloc = 0;
    unsigned allocations = 0;
};

// One full sweep that keeps every candidate. Called sequentially only, so the
// baseline is zero and these numbers belong to this single call.
bool fullSweep(const mfc_flipper::Sample &s, CollectCtx &ctx, const char *name,
               MemoryReport &mem) {
    ctx.keys.clear();
    ctx.keys.reserve(200000); // pre-size so the sink itself never allocates mid-sweep
    ctx.present = false;
    const size_t baseline = gLive.load();
    const unsigned newBefore = gGlobalNewCalls.load();
    const unsigned allocBefore = gAllocations.load();
    gPeak.store(baseline); // measure this call, not the process history
    gMaxAlloc.store(0);
    const mfc_flipper::Result r =
        mfc_flipper::enumerateKeys(s, collectSink, &ctx, nullptr, nullptr);
    mem.peak = gPeak.load() - baseline;
    mem.maxAlloc = gMaxAlloc.load();
    mem.allocations = gAllocations.load() - allocBefore;
    if (gGlobalNewCalls.load() != newBefore) {
        ++gFailures;
        printf("  check failed: solver used operator new during enumeration\n");
    }
    printf("%s: nt=%08X ks=%08X par=%u candidates=%zu present=%s result=%d\n", name, s.nt,
           s.nt ^ s.ntEnc, (unsigned)s.parBits, ctx.keys.size(),
           ctx.want ? (ctx.present ? "1" : "0") : "n/a", (int)r);
    printf("peak_scratch_bytes=%zu max_alloc_bytes=%zu\n", mem.peak, mem.maxAlloc);
    return r == mfc_flipper::Result::Ok;
}

// Shared memory assertions for every measured sweep.
void checkMemory(const MemoryReport &mem, const char *name) {
    check(mem.peak <= kScratchBudget, "peak scratch <= 61440");
    check(mem.maxAlloc <= kMaxAllocationBudget, "max single allocation <= 16384");
    check(mem.peak == mfc_flipper::scratchBytes(), "peak equals the documented total");
    check(mem.maxAlloc == mfc_flipper::maxAllocationBytes(),
          "largest block equals the documented block size");
    check(mem.allocations >= 2, "scratch is split into many blocks");
    check(gLive.load() == 0, "scratch released");
    printf("%s memory: peak=%zu max_alloc=%zu allocations=%u (budget %zu / %zu)\n", name, mem.peak,
           mem.maxAlloc, mem.allocations, kScratchBudget, kMaxAllocationBudget);
}

// Cancellation after the first candidate.
struct CancelCtx {
    unsigned sinkCalls = 0;
    unsigned progressCalls = 0;
    unsigned cancelAtCandidate = 0; // 0 = cancel on the first progress poll
};

bool cancelSink(const uint8_t[6], void *ctx) {
    static_cast<CancelCtx *>(ctx)->sinkCalls++;
    return false;
}

bool cancelProgress(unsigned, unsigned, void *ctx) {
    CancelCtx *c = static_cast<CancelCtx *>(ctx);
    ++c->progressCalls;
    if (c->cancelAtCandidate == 0) return false;          // before anything is emitted
    return c->sinkCalls < c->cancelAtCandidate;           // else cancel on that candidate
}

// Deterministic pseudo-random inputs; no dependency on the host RNG.
// 48-bit key mask for generated keys (not a key value).
constexpr uint64_t kKeyMask = 0x0000FFFFFFFFFFFFULL;

struct Lcg {
    uint64_t state;
    uint32_t next() {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        return (uint32_t)(state >> 32);
    }
    uint32_t word() { return next() ^ (next() >> 7); }
};

} // namespace

int main() {
    printf("module reports: scratch_bytes=%zu max_alloc_bytes=%zu\n", mfc_flipper::scratchBytes(),
           mfc_flipper::maxAllocationBytes());

    // --- 1. Synthetic vector: true key must be in the enumerated set. --------
    {
        const Vector v{0x1F47B5D9u, 0x01200145u, 0x112233445566ULL};
        const mfc_flipper::Sample s = sampleFor(v);
        CollectCtx c;
        c.want = v.key;
        MemoryReport mem;
        const bool ok = fullSweep(s, c, "vector1", mem);
        check(ok, "vector1 result is Ok");
        check(c.present, "vector1 true key present");
        check(!c.keys.empty() && c.keys.size() < 200000, "vector1 candidate count plausible");
        checkMemory(mem, "vector1");
        check(equivalentToProvenSolver(s, c.keys, "vector1"), "identical to proven solver");
    }

    // --- 2. >= 20 random (uid, nt, key) triples -----------------------------
    {
        constexpr unsigned kRandomVectors = 20;
        std::vector<Vector> vectors;
        Lcg rng{0x9E3779B97F4A7C15ULL};
        for (unsigned i = 0; i < kRandomVectors; ++i) {
            Vector v;
            v.uid = rng.word();
            v.nt = rng.word();
            v.key = ((uint64_t)rng.word() << 16) ^ rng.word();
            v.key &= kKeyMask;
            vectors.push_back(v);
        }
        // Independent per vector, so run them concurrently; each call allocates
        // its own scratch block through the counting hook.
        std::atomic<unsigned> passed{0};
        const unsigned workers = 4;
        std::vector<std::thread> pool;
        std::atomic<unsigned> next{0};
        for (unsigned w = 0; w < workers; ++w) {
            pool.emplace_back([&]() {
                for (;;) {
                    const unsigned i = next.fetch_add(1);
                    if (i >= vectors.size()) return;
                    const mfc_flipper::Sample s = sampleFor(vectors[i]);
                    AcceptCtx c;
                    c.want = vectors[i].key;
                    const mfc_flipper::Result r =
                        mfc_flipper::enumerateKeys(s, acceptSink, &c, nullptr, nullptr);
                    const bool hit = r == mfc_flipper::Result::Ok && pack(c.got) == vectors[i].key;
                    if (hit) ++passed;
                    printf("random%02u: uid=%08X nt=%08X result=%d present=%d\n", i,
                           vectors[i].uid, vectors[i].nt, (int)r, hit ? 1 : 0);
                }
            });
        }
        for (auto &t : pool) t.join();
        printf("random vectors: %u/%u present=1\n", passed.load(), kRandomVectors);
        check(passed.load() == kRandomVectors, "every random vector finds the true key");
    }

    // --- 3. Static-nonce vector: the real hardware sample window ------------
    // uid/nt/keystream/parity are the values the ST25R3916 logged for the lab
    // card (nt=01200145 enc=044C698A ks=056C68CF par=001). No key material:
    // whatever key the card holds must be re-discovered by the enumeration and
    // is then re-checked here against Crypto1 by the test itself.
    {
        mfc_flipper::Sample s;
        s.uid = 0x1F47B5D9u;
        s.nt = 0x01200145u;
        s.ntEnc = 0x01200145u ^ 0x056C68CFu; // enc=044C698A as logged
        s.parBits = 0x4;                     // par printed as 0,0,1 -> bit2
        CollectCtx c;
        MemoryReport mem;
        const bool ok = fullSweep(s, c, "static-hw-sample", mem);
        check(ok, "static hardware sample produces candidates");
        check(!c.keys.empty(), "static hardware sample: at least one consistent key");
        checkMemory(mem, "static-hw-sample");

        // Independent soundness check: every offered candidate must reproduce
        // the logged window. A false positive here would mean a bad solver.
        unsigned bad = 0;
        for (const uint64_t k : c.keys) {
            uint8_t raw[6];
            for (int i = 0; i < 6; i++) raw[i] = (uint8_t)(k >> ((5 - i) * 8));
            if (!reproducesWindow(raw, s)) ++bad;
        }
        printf("static-hw-sample: candidates=%zu rejected_by_independent_check=%u\n", c.keys.size(),
               bad);
        check(bad == 0, "no candidate contradicts the logged window");
        check(equivalentToProvenSolver(s, c.keys, "static-hw-sample"),
              "static sample matches the proven solver exactly");
    }

    // --- 4. Determinism -----------------------------------------------------
    {
        const Vector v{0xDEADBEEFu, 0x89ABCDEFu, 0xD3F7D3F7D3F7ULL};
        const mfc_flipper::Sample s = sampleFor(v);
        CollectCtx a, b;
        a.want = v.key;
        b.want = v.key;
        MemoryReport mem1, mem2;
        fullSweep(s, a, "determinism/run1", mem1);
        fullSweep(s, b, "determinism/run2", mem2);
        checkMemory(mem2, "determinism");
        check(a.keys.size() == b.keys.size(), "same candidate count");
        check(a.keys == b.keys, "same candidate sequence");
        check(a.present && b.present, "true key present both times");
        printf("determinism: counts=%zu/%zu identical=%d\n", a.keys.size(), b.keys.size(),
               a.keys == b.keys ? 1 : 0);
    }

    // --- 5. Cancellation ----------------------------------------------------
    {
        const Vector v{0x1F47B5D9u, 0x01200145u, 0x0BADF00D5EEDULL};
        const mfc_flipper::Sample s = sampleFor(v);
        CancelCtx immediate;
        immediate.cancelAtCandidate = 0;
        const mfc_flipper::Result r0 =
            mfc_flipper::enumerateKeys(s, cancelSink, &immediate, cancelProgress, &immediate);
        printf("cancel/before-first: result=%d sink_calls=%u\n", (int)r0, immediate.sinkCalls);
        check(r0 == mfc_flipper::Result::Cancelled, "cancel before work -> Cancelled");
        check(immediate.sinkCalls == 0, "cancel before work -> no sink calls");

        CancelCtx afterFirst;
        afterFirst.cancelAtCandidate = 1;
        const mfc_flipper::Result r1 =
            mfc_flipper::enumerateKeys(s, cancelSink, &afterFirst, cancelProgress, &afterFirst);
        printf("cancel/after-candidate1: result=%d sink_calls=%u progress_calls=%u\n", (int)r1,
               afterFirst.sinkCalls, afterFirst.progressCalls);
        check(r1 == mfc_flipper::Result::Cancelled, "cancel after candidate 1 -> Cancelled");
        check(afterFirst.sinkCalls == 1, "cancel after candidate 1 -> exactly one sink call");
    }

    // --- 6. Input validation ------------------------------------------------
    {
        mfc_flipper::Sample s{0x1F47B5D9u, 0x01200145u, 0x044C698Au, 0x4};
        const mfc_flipper::Result noSink = mfc_flipper::enumerateKeys(s, nullptr, nullptr);
        check(noSink == mfc_flipper::Result::InvalidInput, "null sink -> InvalidInput");
        CancelCtx unused;
        s.parBits = 8;
        const mfc_flipper::Result badParity =
            mfc_flipper::enumerateKeys(s, cancelSink, &unused);
        check(badParity == mfc_flipper::Result::InvalidInput, "parBits > 7 -> InvalidInput");
        printf("validation: null_sink=%d par_bits_8=%d\n", (int)noSink, (int)badParity);
    }

    if (gFailures) {
        printf("FAIL: %d check(s)\n", gFailures);
        return 1;
    }
    printf("PASS: mfc_flipper host tests\n");
    return 0;
}
