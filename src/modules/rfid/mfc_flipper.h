// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Low-memory MIFARE Classic key enumeration for static-PRNG cards.
//
// Origin (GPL-3.0), ported and adapted 2026-11-03:
//   * flipperdevices/flipperzero-firmware, lib/nfc/helpers/crypto1.c
//     https://github.com/flipperdevices/flipperzero-firmware/blob/8427ec009812/lib/nfc/helpers/crypto1.c
//   * flipperdevices/flipperzero-good-faps, mfkey/ (mfkey.h, mfkey_attack.c,
//     mfkey_recovery.c, mfkey_state_expansion.c), commit 55328b486971
//     https://github.com/flipperdevices/flipperzero-good-faps/tree/55328b486971/mfkey
//   * local provenance: src/modules/rfid/mfc_recovery.{h,cpp} (GPL-3.0-only),
//     whose single-sample enumeration recovered sector 1 on the lab card.
//
// Bruce itself is AGPL-3.0, so this file and the work that links it are
// distributed as AGPL-3.0. Both upstream licences are GPL-3.0, which the
// AGPL-3.0 permits combining with (GPL-3.0 section 13).
//
// Distributed WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
//
// What this is: the memory architecture of Flipper's mfkey app (packed 24-bit
// candidate states, a bounded per-MSB-band sweep, no sorting scratch) applied
// to the single-keystream-window enumeration that this repo already proved on
// hardware. Candidate keys are NOT verified here: the caller must verify each
// one by a real authentication, exactly as the hardware path does.
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace mfc_flipper {

// One authentication sample from a card whose nonce does not change.
struct Sample {
    uint32_t uid;    // card UID as a big-endian word (0x1F47B5D9 for the lab card)
    uint32_t nt;     // plaintext tag nonce, big-endian byte order
    uint32_t ntEnc;  // nonce as encrypted by the card (keystream = nt ^ ntEnc)
    uint8_t parBits; // 3 transmitted nonce parity bits; bit0 = MSB byte of nt.
                     // Must be in 0..7 (a value > 7 is rejected, not masked).
};

enum class Result {
    Ok,          // enumeration finished and offered at least one candidate
    NoCandidates,// enumeration finished without a single consistent key
    NoMemory,    // scratch unavailable, or the fixed candidate capacity was
                 // exceeded (NOT an exhaustive search: never read as "no key")
    InvalidInput,// null sink, or parBits > 7
    Cancelled,   // Progress returned false
};

// Return true to stop the search on this candidate (found / accepted).
using CandidateSink = bool (*)(const uint8_t key[6], void *ctx);
// Return false to cancel. Called at least every 4096 enumerated semi-states and
// after every candidate. `done` counts finished buckets of `total` (256).
using Progress = bool (*)(unsigned done, unsigned total, void *ctx);

// Band boundary report. The sweep runs 32 bands of 8 MSB buckets; a band is the
// only place the solver does long work with no candidate to offer, so its start
// and end are the boundaries a stall watchdog has to see. Called twice per band,
// with `finished` false before the 2^20 semi-state sweep and true after the
// band's eight buckets have been joined.
struct BandReport {
    unsigned band;       // 0..31
    bool finished;       // false = sweep about to start, true = buckets joined
    unsigned candidates; // candidates offered to the sink so far
    unsigned bucketMax;  // largest per-bucket candidate table this band required
    bool overflow;       // fixed capacity was exceeded -> Result::NoMemory
};
using BandReporter = void (*)(const BandReport &report, void *ctx);

// Enumerate every key consistent with the sample's 32-bit keystream window and
// its three parity bits. Keys are six bytes, most significant byte first.
// Emission order is deterministic for a given sample.
//
// Scratch is requested as small fixed blocks (the MFKey shape): 16 bucket
// blocks plus 2 work blocks, 53,248 B in total, no block larger than 5,120 B.
// Nothing else is allocated. Verification is deliberately NOT part of this
// module.
Result enumerateKeys(const Sample &s, CandidateSink sink, void *ctx,
                     Progress progress = nullptr, void *progressContext = nullptr,
                     BandReporter bandReporter = nullptr, void *bandContext = nullptr);

// Total scratch the solver requests, in bytes (<= 61440).
size_t scratchBytes();

// Largest single scratch block the solver requests, in bytes (<= 16384).
size_t maxAllocationBytes();

} // namespace mfc_flipper
