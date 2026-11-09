# MIFARE Classic key recovery on the Cardputer ADV

Working notes for the MIFARE Classic key-recovery feature in this fork.
Status as of 2026-11-06. Hardware: M5Stack Cardputer ADV (ESP32-S3, no
PSRAM) with an ST25R3916 NFC front end over I2C.

Everything here was measured on hardware unless marked otherwise.

## 1. What works today

- A single sector's key can be recovered and the sector then read.
  Proven on the real card with two different solver implementations, and a
  full 66,000-candidate sweep has now completed end to end.
- The card is never written to. No erase, no clone, no write path invoked.

| Command | Result |
|---|---|
| `rfid recover 5000 1` | `static -> Verified`, `New keys recovered: 1` |
| `rfid read 5000` | `Pages: 28`, `Total pages: 64`, blocks 4-7 print real data |
| `rfid recover 5000 5` | `static -> Verified` after 77,312 candidates, `New keys recovered: 1` |

Readable sectors: 0, 1, 2, 3, 4, 5, 14, 15 (32 of 64 blocks). The rest are
locked with keys the card does not give up cheaply.

Verified keys are persisted per card at `/BruceRFID/mfc_keys/<UID>.txt` (SD, or
LittleFS when no card is mounted). A plain read loads them and tries the key
that fits each sector before the dictionary, so a reboot costs a read instead of
another 78-minute sweep. `rfid mfckeys show` lists which sectors are known and
never prints a key.

## 2. The card

MIFARE Classic 1K clone, UID `1F 47 B5 D9`, SAK `08`, ATQA `04 00`.

Its PRNG is **static**: every authentication returns the same nonce
`01200145`, for every block, in every session. That single property decides
which attacks are possible.

Known keys, all from the default dictionary or prior recovery:

| Sector | Key A |
|---|---|
| 0, 2 | `A0A1A2A3A4A5` |
| 3, 4, 14, 15 | `FFFFFFFFFF` |
| 1 | recovered on 2026-11-03, value in local evidence logs only |

## 3. Which attacks work here

| Attack | Needs | Verdict on this card |
|---|---|---|
| Nested | Two different nonces from the same PRNG stream | **Impossible.** The nonce never changes |
| Darkside | A parity oracle: the tag answers deliberately corrupted parity with an encrypted 4-bit NAK | **Dead.** 419 probes produced no usable NAK chain |
| Dictionary | Nothing | Works, but only for the 6 default-key sectors |
| Single-sample enumeration | One known key plus one captured nonce under the target key | **Works.** Recovered sector 1 in 180 s |

The last one is what the firmware implements. Because the nonce is fixed, the
plaintext nonce is already known, so one captured encrypted nonce yields 32
bits of keystream directly. That pins the key to roughly 66,000 candidates,
and each candidate is checked with a real authentication, so a wrong answer
cannot survive.

## 4. Code layout

| File | Role |
|---|---|
| `src/modules/rfid/crypto1.cpp` | Crypto1 cipher, filter, PRNG successor |
| `src/modules/rfid/mfc_flipper.cpp` | Candidate solver, ported from the Flipper Zero MFKey app's memory architecture |
| `src/modules/rfid/mfc_recovery.cpp` | Earlier solver, bounded-memory enumeration, host tests |
| `src/modules/rfid/mfc_darkside.cpp` | Darkside solver, retained for cards that have an oracle |
| `src/modules/rfid/ST25R3916.cpp` | Driver: select, auth, encrypted transceive, read |
| `src/core/serial_commands/rfid_commands.cpp` | `rfid mfc*` and `rfid recover` commands |
| `tests/run_native_mfc_tests.sh` | Host tests, no hardware needed |

### Why the solver was reimplemented

The first solver asked the heap for one contiguous 98 KiB block. After a card
read, the heap is fragmented and that request fails, which surfaced as
`static -> NoMemory` in the middle of a recovery. Reserving the block at
startup fixed it but held 98 KiB permanently, dropping free memory from
160 KiB to about 62 KiB for the whole session.

The replacement ported the memory shape from Flipper's MFKey app: pack
candidates into 24-bit states, split the sweep into MSB buckets, and ask for
many small fixed blocks instead of one large one. Measured on host:
**53,248 bytes peak, largest single allocation 5,120 bytes, 18 allocations.**
Free heap during recovery is 143,884 bytes.

The host test asserts that the new solver emits the identical candidate
sequence as the old one, so the rewrite changed memory layout only, not math.

## 5. Cost model

The expensive part is airtime, not computation. Every candidate needs a real
exchange with the card: wake it, select it, attempt an authentication.

| Step | Measured |
|---|---|
| Wake + select (WUPA + SELECT) | 23.3 ms |
| Authentication attempt (auth + AT) | 24.0 ms |
| Candidates per second | 17-18 |
| Full 77,312-candidate sweep | 78 minutes |
| Dictionary pre-pass before the crypto stage | about 15 minutes |

`rfid mfcbench` (added 2026-11-06) breaks the per-frame cost down so it can be
argued about instead of guessed:

| Measurement | Value | Reading |
|---|---|---|
| One polled IRQ register read | 400 us | ~200 us per I2C transaction, near wire time at 400 kHz |
| Frame the card ignores, FWT 3 ms | 13.0 ms | |
| Same frame, FWT 10 ms | 20.1 ms | slope is exactly 7 ms: the RX wait honours the timeout |
| Fixed cost per frame | **10.0 ms** | everything that is not waiting for the card |
| - `rfalStartTransceive` | 2.8 ms | chip setup before the frame |
| - first `rfalWorker()` call | 5.5 ms | more setup, frame transmit, TXE wait |
| - FWT polling | 3.0 ms | 15 iterations at ~320 us |

So a frame costs ~10 ms of reader work plus ~1.5 ms of air, and a candidate
needs four frames (WUPA, SELECT, auth, AT) = ~48 ms. Two consequences:

- **The card sets the pace, and it will not be short-circuited.** Measured:
  after a wrong-key NAK the card answers *nothing* for 29 of 30 back-to-back
  authentications, so every candidate must re-select. WUPA and SELECT cannot
  be skipped.
- **The 10 ms is I2C transaction traffic, not radio.** RFAL re-writes the
  same registers before every frame over a 400 kHz bus that has no interrupt
  line. A lean transceive path (configure once, then FIFO + transmit + poll)
  is the only remaining speed lever; it was not attempted here because the
  working path already recovers a sector in 78 minutes and rewriting RFAL's
  TX path risks the one thing that works.

Earlier the same numbers were 67.8 ms and 66.3 ms per step, about 5
candidates per second. The fix was the I2C bus: 100 kHz was the default. At
400 kHz (the ST25R3916 fast-mode limit) the cost per step fell by two thirds.

## 6. Hardware facts worth keeping

- Receive lengths, measured over thousands of exchanges: plain nonce 36 bits,
  encrypted nonce 36 bits, authentication answer (AT) 36 bits or a 4-bit NAK,
  block read 162 bits. Checks now use these exact values, not `>=`.
- The first check written as `144` (18 bytes, no parity) broke reads
  completely: `rfid read` returned `Pages: 0`. 162 is the correct number
  because 16 data bytes, 2 CRC bytes and 18 parity bits all arrive.
- One missed reselect used to abandon a whole sector. A card read recovered
  from 4/64 blocks to 24/64 once the read path retried with
  `_mfcReacquire(1500, 2)` and retried the sector once instead of skipping it.
- The clone stops answering a bare authentication after a failed attempt, so
  every miss needs a fresh anticollision.
- There is no PSRAM. Solver scratch must come from the internal heap, and
  allocation shape matters as much as allocation size.

## 7. Resolved: the silent stall on unknown sectors

Sweeps of unknown sectors used to stop producing output and never finish.
Sector 5 died at `tries=17920`, sector 6 at `tries=12032`, with no panic, no
backtrace, no watchdog reset and stable heap.

Cause: `Serial.printf` on the USB CDC console blocks forever once the host
stops draining the port. The sweep logs progress every 256 candidates, so a
disconnected or busy host wedged the firmware inside a log line: the card was
fine, the CPU was fine, and the output simply stopped because the writer was
stuck. Every stall ended on a normal progress line, which is exactly what a
blocked writer looks like.

Fix (commit `8b7feaa`): every log site checks `Serial.availableForWrite()`
first and drops the line instead of blocking, so a host that stops reading can
never stop the sweep. Confirmed by a sweep that ran from 17,920 to 77,312
candidates without a gap and recovered sector 5's key.

## 8. What is not verified

- Sectors 6 through 13: recovery running, one sector per ~78 minutes.
- Sector 5 Key B: never attempted. Key A is enough to read the sector.
- `rfid recover` with no sector argument (`recoverAllKeys`): untested.
- Any card other than this one. Non-static-PRNG cards would take a different
  path.
- The 4-bit write acknowledgement path: no writes are ever executed.

## 9. Running it

Build and flash:

```
pio run -e m5stack-cardputer-adv -j 4
python3 scripts/cardputer_device.py flash --port /dev/cu.usbmodem101 \
    --image Bruce-m5stack-cardputer-adv.bin \
    --existing-backup <8mb-backup>.bin
```

Host tests, no hardware required:

```
./tests/run_native_mfc_tests.sh
```

On the device:

```
rfid mfckey <block> A <12-hex-key>          # verify one key, prints PASS/FAIL only
rfid mfcstatic <knownBlk> A <key> <targetBlk> A   # recover one sector's key
rfid mfcaddkey <12-hex-key>                 # load a key for the next read
rfid mfckeys [save|load|show]               # per-card key sidecar; show never prints keys
rfid recover <ms> <sector>                  # full path: scan, recover, verify
rfid read <ms>                              # dump the card
rfid mfcbench [okBlk] [nakBlk]              # timing breakdown, read-only
```

## 10. Rules this project learned the hard way

1. Read the vendored function before calling it. Never infer behaviour from a
   name. The RFAL fork is patched and differs from upstream documentation.
2. Every primitive returns a reason, not a boolean. A step code turns one
   flash cycle into five answers.
3. Assert the positive signal. `Static result: Verified`, not "no error
   appeared". The test harness used to score `New keys recovered: 0` as a
   pass, which hid a real failure.
4. Measure before optimizing. One instrumented build replaced a 3.6-hour
   guess with a 3x fix.
5. Exact frame lengths, taken from measurement, not from theory. A guessed
   `144` broke reads until it was measured as `162`.
6. A record that "works" only in the lucky case is not working. Sector 1's
   key arrived at candidate 3,260 of 66,000; everything past that point was
   never exercised until it failed.

## 11. Evidence

Local evidence lives in `~/.local/state/cardputer/`, one directory per run.
Keys appear in those logs and are redacted from anything shared.

| Run | What it proves |
|---|---|
| `20261103-195631-519252-test` | first successful key recovery, 3,260 candidates, 180 s |
| `20261103-201400-590341-test` | fresh authentication with the recovered key, full sector read |
| `20261103-192758-202285-test` | read-robustness fix, 4/64 to 24/64 blocks |
| `20261104-090442-279601-test` | reimplemented solver recovers the same key, `Pages: 28` |
| `20261104-092505-114862-test` | sector 5 stall |
| `20261104-100626-149324-test` | sector 6 stall |
| `20261105-223653-686729-test` | sector 5 recovered by a full 77,312-candidate sweep, `static -> Verified` |
| `20261106-204553-777088-test` | `rfid mfcbench`: per-frame cost model; card refuses auth without a fresh select |
