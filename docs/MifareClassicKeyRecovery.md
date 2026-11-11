# MIFARE Classic key recovery on the Cardputer ADV

This is the state of record for the MIFARE Classic key-recovery work in this
fork: what it does, how it is built, how it is tested, and what is still
unproven. Status as of 2026-11-09. Hardware: M5Stack Cardputer ADV (ESP32-S3,
no PSRAM) with an ST25R3916 NFC front end over I2C.

Everything here was measured on hardware unless marked otherwise. Key values
never appear in this file, in commits, in reports, or in release assets.

## 1. What it does, in one paragraph

`RFID → Read tag` reads whatever the card gives up. If sectors are still
locked, the same screen then says how many and what a sweep would cost, and
waits for an explicit OK. On OK the firmware takes each locked sector and tries
the cheapest attack first — reuse of an already-known key, then nested
authentication, then single-keystream enumeration for static-PRNG clones, then
darkside. Every key is proven with a real authentication before it is accepted,
written to a per-card sidecar file the moment it verifies, and the card is
re-read at the end so the result is a block count rather than a claim. The card
is never written to: no erase, no clone, no write command.

## 2. Where the feature lives

| Concern | File |
|---|---|
| UI: offer, progress screen, result screen | `src/modules/rfid/tag_o_matic.cpp` (`offer_mfc_recovery`) |
| UI state/fields | `src/modules/rfid/tag_o_matic.h` (`_mfcOfferUID`) |
| Menu | `src/core/menu_items/RFIDMenu.cpp` — **no dedicated entry**, by design |
| Driver: select/auth/transceive/read | `src/modules/rfid/ST25R3916.cpp` |
| API + dumps | `src/modules/rfid/ST25R3916.h` (`MifareClassicDump`) |
| Attack orchestration | `ST25R3916::recoverSectorKeys`, `recoverAllKeys` |
| Crypto1 + candidate solver | `src/modules/rfid/crypto1.cpp`, `mfc_flipper.cpp` |
| Earlier bounded-memory solver | `src/modules/rfid/mfc_recovery.cpp` |
| Darkside solver | `src/modules/rfid/mfc_darkside.cpp` |
| Serial commands | `src/core/serial_commands/rfid_commands.cpp` |
| Device harness | `scripts/cardputer_device.py` |
| Test scripts | `scripts/mfc-test/` |
| Host tests | `tests/run_native_mfc_tests.sh` |

`ST25R_RECOVERY_LOG` is private to `ST25R3916.cpp`. From `tag_o_matic.cpp` use
`Serial.printf` — the macro is not visible there and the build fails if you try.

## 3. End-to-end flow

```
RFID menu
  └─ Read tag                      (ordinary TagOMatic READ_MODE)
       ├─ _rfid->read()            dictionary keys + saved sidecar keys
       ├─ dump_card_details()      UID, SAK, pages
       └─ offer_mfc_recovery()     only if this is MIFARE Classic
            ├─ locked == 0  ─────► return, nothing shown
            ├─ already offered for this UID ─► return (once per placement)
            └─ offer screen
                 "Sectors: 16  locked: 5"
                 "Keys known: 10"
                 "~62 min per locked sector"
                 "~5 h 10 m total"
                 "Card is never written to"
                 "[OK] recover   [ESC] read only"
                   │
                   ├─ ESC ─► back to the read screen, read-only
                   └─ OK  ─► per locked sector, cheapest first:
                              1/3 nested auth     (fails fast here)
                              2/3 static sweep    n/77312, ~min left
                              3/3 darkside        last resort
                             each verified key → sidecar immediately
                             ▼
                          re-read, then
                          "RECOVER DONE / Keys found: n / Keys known: m
                           Pages: 40/64 / Saved: /BruceRFID/mfc_keys"
```

Design constraints that shaped this:

- **No separate menu entry.** The user asked for recovery to be offered inside
  `Read tag`, not as its own mode. `READ_RECOVER_MODE` was removed; a grep for
  it must return nothing.
- **Offer once per placement.** `read_card()` runs every ~2 s while the card
  sits in the field, so an offer that reappeared each pass would be a trap.
  Removal of the card (`TAG_NOT_PRESENT`) clears `_mfcOfferUID` and re-arms it.
- **The OK/ESC choice is captured once.** `check()` clears the key flag it
  reads, so testing `EscPress` again after the wait would always read false and
  start a 5-hour sweep on an ESC press. The gate exists to prevent exactly that.
- **ESC during a sweep** makes the progress callback return false, which sets
  the solver's abort flag and surfaces as `Cancelled` (`-2`): the current sector
  stops, keys already found stay saved.

## 4. Algorithm order, and why it is that order

`recoverSectorKeys(sector)` for each key type still missing:

| # | Attack | Cost here | Condition |
|---|---|---|---|
| 0 | Reuse a key already in memory (`_mfcAdoptKnownKey`) | 1 auth, ~58 ms | always tried first; clones repeat keys |
| 1 | Nested authentication (`recoverKey`) | seconds when possible | needs two different plaintext nonces |
| 2 | Single-keystream enumeration (`recoverKeyStaticNonce`) | 77,312 candidates, ~62-78 min | only when nonce distance is 0 |
| 3 | Darkside (`recoverKeyDarkside`) | open-ended | needs a parity oracle |

Two things about the order are deliberate and were learned the hard way:

- **Nested before static.** Nested is free when it works, and it fails in
  seconds with `dist=0` on this card. The static sweep is only started after
  that failure is on record (logged as `trying static-nonce (dist=0)`).
- **Darkside last, not second.** Darkside runs many short transceives and
  fragments the heap; the enumeration that follows it then cannot allocate.
  Ordering it after the sweep is a memory decision, not a preference.

The screen maps the live driver phase to a step number so the order is visible
rather than implied (`mfcPhaseStep` / `mfcPhaseLabel` in `tag_o_matic.cpp`):

| Driver phase | Screen label | Step |
|---|---|---|
| `auth1`, `at`, `wupa`, `select`, `halt` | raw phase name, no step | — |
| `nested`, `solve` | `nested auth` / `solving` | 1/3 |
| `sink` | `static sweep` | 2/3 |
| `darkside` | `darkside` | 3/3 |

`Sectors: N, locked: M` is recomputed from `mfcDump.keyAFound/keyBFound` after
the read, so a sector opened by a saved key or the dictionary is not offered
for recovery at all.

## 5. Persistence design

A full sweep is hours, so a key that is not written down is lost work: the dump
file stores blocks, not keys, and the device is RAM-only otherwise.

- **Location:** `/BruceRFID/mfc_keys/<UID>.txt` — SD when a card is mounted,
  LittleFS otherwise (this unit has no SD, so LittleFS).
- **Format:** `#` comment lines, then one `<A|B> <sector> <12 hex>` per key.
- **Written on:** every `recoverSectorKeys` that found something, and every
  read that opened at least one block (`mfcKeysSaveAll`).
- **Read on:** `_readMifareClassic()`, i.e. the read path — *not*
  `selectMifareClassic()`. That was the first bug: the load was on a path a
  plain read never takes, so persistence appeared to do nothing.
- **A saved key is a guess until the card proves it.** Loading fills a
  per-sector table (`_mfcSideKeyA/B`, `_mfcSideHaveA/B`) and never sets
  `keyAFound`. The read tries the one key that fits the sector before the
  55-key dictionary, and only an actual authentication marks it found.
  Otherwise a card that shares a UID but not a key would silently report more
  readable sectors than it has.
- **Saves merge, never replace.** A read that ends early must not erase keys
  already proven, so `mfcKeysSaveAll()` writes the union of what is proven now
  and what was already in the sidecar.
- **Never printed.** `rfid mfckeys show` lists sector and type only.
- **Flashing erases them.** The filesystem partition is inside the merged
  image. Reboots and power cycles keep them; reflashing does not.

The second bug was a line-length guard: requiring 17 characters dropped every
single-digit sector while two-digit sectors loaded, i.e. "persistence mostly
works". Both fixes are in `faeece5` and `041065c`.

## 6. Stall detection and its limit

Sweeps used to go silent: sector 5 died at `tries=17920`, sector 6 at
`tries=12032`, no panic, stable heap. Cause: `Serial.printf` on the USB CDC
console blocks forever once the host stops draining the port, and the sweep
logs every 256 candidates.

Fix (commit `8b7feaa`): every log site checks `Serial.availableForWrite()`
first and drops the line rather than blocking.

On top of that, `_mfcMonitorTask` is an independent FreeRTOS task (core 0) that:

- prints a `beat` line every 30 s with the live phase, band, bucket, candidate
  count and free heap — proof of life that does not touch the card;
- treats 10 s without a beat as a stall (`30 s` during the `solve` phase, which
  is legitimately quiet), dumps the state once, then sets `gMfcAbort`.

**Known limit, measured 2026-11-08.** The watchdog only helps where the code
returns to a place that checks `gMfcAbort`. A sector-8 sweep froze after 10,524
candidates in phase `at`: 3.6 hours with `tried` unchanged and heap stable at
147,488, while the monitor kept printing. The abort flag was set and never
observed, because the sweep was wedged inside the transceive path. That is a
real hang, not slowness, and it makes a multi-hour unattended run unsafe on this
card. Untangling it is the next piece of work.

## 7. The card

MIFARE Classic 1K clone, UID `1F 47 B5 D9`, SAK `08`, ATQA `04 00`.

Its PRNG is **static**: every authentication returns the same nonce
`01200145`, for every block, in every session. That single property decides
which attacks are possible.

Known keys, all from the default dictionary or prior recovery (values local
only):

| Sector | Key A origin |
|---|---|
| 0, 2 | default `A0A1A2A3A4A5` |
| 3, 4, 14, 15 | default `FFFFFFFFFFFF` |
| 1, 5, 6, 7 | recovered on-device, stored in the sidecar |

## 8. Which attacks work here

| Attack | Needs | Verdict on this card |
|---|---|---|
| Nested | Two different nonces from the same PRNG stream | **Impossible.** The nonce never changes |
| Darkside | A parity oracle: the tag answers deliberately corrupted parity with an encrypted 4-bit NAK | **Dead.** 419 probes produced no usable NAK chain |
| Dictionary | Nothing | Works, but only for the 6 default-key sectors |
| Single-sample enumeration | One known key plus one captured nonce under the target key | **Works.** Recovered sector 1 in 180 s |

Because the nonce is fixed, the plaintext nonce is already known, so one
captured encrypted nonce yields 32 bits of keystream directly. That pins the key
to roughly 66,000-77,312 candidates, and each candidate is checked with a real
authentication, so a wrong answer cannot survive.

### The abandoned 32-bit offline oracle

An attempt was made to test 32-bit key halves offline against a captured
keystream window without touching the card. It was shaped so a hit would be
unmistakable: 480 probes, zero hits. The "AT mismatch" lines that looked like
partial success were 4-bit NAKs being parsed as 36-bit frames. Recorded here so
nobody re-derives it: on this card the only oracle is a real authentication.

### Card emulation (mfkey32) is not applicable

It requires a second reader that already knows the key. There is one reader.

## 9. Cost model

The expensive part is airtime, not computation. Every candidate needs a real
exchange with the card: wake it, select it, attempt an authentication.

| Step | Measured |
|---|---|
| Wake + select (WUPA + SELECT) | 23.3 ms |
| Authentication attempt (auth + AT) | 24.0 ms |
| Candidates per second | 17-18 |
| Full 77,312-candidate sweep | 62-78 minutes |
| Dictionary pre-pass before the crypto stage | about 15 minutes |

`rfid mfcbench` breaks the per-frame cost down so it can be argued about
instead of guessed:

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
- **The 10 ms is I2C transaction traffic, not radio.** RFAL re-writes the same
  registers before every frame over a 400 kHz bus that has no interrupt line. A
  lean transceive path (configure once, then FIFO + transmit + poll) is the only
  remaining speed lever; it was not attempted because the working path already
  recovers a sector in about an hour, and rewriting RFAL's TX path risks the one
  thing that works.

Earlier the same numbers were 67.8 ms and 66.3 ms per step, about 5 candidates
per second: the I2C bus defaulted to 100 kHz. At 400 kHz (the ST25R3916
fast-mode limit) the cost per step fell by two thirds.

## 10. Solver memory shape

The first solver asked the heap for one contiguous 98 KiB block. After a card
read the heap is fragmented and that request fails, surfacing as
`static -> NoMemory` mid-recovery. Reserving it at startup fixed that but held
98 KiB permanently, dropping free memory from 160 KiB to ~62 KiB.

The replacement ported the memory shape from Flipper's MFKey app: pack
candidates into 24-bit states, split the sweep into MSB buckets, ask for many
small fixed blocks. Host-measured: **53,248 bytes peak, largest single
allocation 5,120 bytes, 18 allocations.** Free heap during recovery: 143,884
bytes. The host test asserts the new solver emits the identical candidate
sequence as the old one, so the rewrite changed layout only, not math.

## 11. Hardware facts worth keeping

- Receive lengths, measured over thousands of exchanges: plain nonce 36 bits,
  encrypted nonce 36 bits, authentication answer (AT) 36 bits or a 4-bit NAK,
  block read 162 bits. Checks use these exact values, not `>=`.
- The first check written as `144` (18 bytes, no parity) broke reads
  completely: `rfid read` returned `Pages: 0`. 162 is correct because 16 data
  bytes, 2 CRC bytes and 18 parity bits all arrive.
- One missed reselect used to abandon a whole sector. A read recovered from
  4/64 to 24/64 blocks once the read path retried with `_mfcReacquire(1500, 2)`
  and retried the sector once instead of skipping it.
- The clone stops answering a bare authentication after a failed attempt, so
  every miss needs a fresh anticollision.
- There is no PSRAM. Solver scratch must come from the internal heap, and
  allocation shape matters as much as allocation size.
- The ST25R3916 sometimes misses the boot-time I2C probe on the first boot
  after a flash (`No I2C devices found`). Power-cycle or retry once; it is not a
  flash failure.

## 12. Serial command reference

Read-only in every case: these authenticate or read.

```
rfid read [ms]                                  read the card, print pages
rfid recover <ms> <sector>                      full path for one sector
rfid recover <ms>                               recoverAllKeys (untested)
rfid mfcstatic <knownBlk> A <key> <targetBlk> A single-keystream recovery
rfid mfckey <block> A <12-hex>                   verify one key, PASS/FAIL only
rfid mfcaddkey <12-hex>                          load a key for the next read
rfid mfckeys [save|load|show]                    per-card sidecar; show never prints keys
rfid mfcdarkside <blk> A                         darkside attempt
rfid mfcbench [okBlk] [nakBlk]                   per-frame timings
rfid mfcmeasure                                  raw frame timing samples
rfid mfcscan                                     scan for cards
rfid mfcsample <blk>                             capture one nonce sample
rfid mfcwire                                     wiring/register sanity
rfid mfcdiag                                     reader diagnostics
```

UI counterpart: `Read tag` → offer → OK runs the loop above without a serial
host attached.

## 13. Testing

### Device harness: `scripts/cardputer_device.py`

```
flash                 write a merged image at 0x0, verify by reading it back
test                  boot checks + optional RFID read + scripted commands
probe                 connect and report what the reader says
```

Useful flags: `--port`, `--image`, `--existing-backup <8mb.bin>`, `--rfid`,
`--require-tag`, `--skip-read`, `--rfid-command "<cmd>"` (repeatable),
`--command-timeout`, `--recover`, `--recover-sector`, `--recover-timeout`.

Scoring is on positive output, never on the absence of an error:

| Command | Counts as PASS only when |
|---|---|
| `rfid mfckey` | output contains `: PASS` |
| `rfid mfcstatic` | `Static result: Verified` |
| `rfid mfcdarkside` | `Darkside result: Verified` or `AlreadyKnown` |
| `rfid read` | `Pages: N` with N > 0 |
| `rfid recover` | `New keys recovered: N` with N > 0 |
| anything else | non-empty output with no `ERROR`/`FAIL`/`failed` |

A missing tag is recorded as `BLOCKED`, never `PASS`. Output goes to
`~/.local/state/cardputer/<stamp>-<action>/`, with `serial-transcript.log` as
the file to read when the score disagrees with what happened.

One known harness quirk: `rfid mfckeys show` falls through to the generic
matcher and can print FAIL while the transcript is correct, because the command
prints sector numbers and no error. Read the transcript. Note that
`New keys recovered: 0` is a genuine FAIL by design — a sector whose key was
already in the sidecar produces exactly that, so score a sweep by the
`static -> Verified` lines and the resulting `Pages:` count.

### Test scripts

```
# 3-minute persistence proof: read → reboot → read, no sweep
PORT=/dev/cu.usbmodem101 scripts/mfc-test/run-persist-test.sh

# sweep locked sectors; keys are saved per sector as they verify
PORT=/dev/cu.usbmodem101 SECTORS="8 9 10" scripts/mfc-test/run-fullcard-sweep.sh
```

Environment: `PORT`, `STATE_DIR` (default `~/.local/state/cardputer`),
`SECTORS`, `TIMEOUT` (default 10800 s), `KNOWN_KEYS_FILE` / `EXTRA_KEYS_FILE`
(optional local file of `Key A sector <n>: AA BB CC DD EE FF` lines, read but
never printed and never committed), `LONG=1` to continue past a failed sector.

`run-persist-test.sh` proves the right thing by construction: session A writes
the sidecar, then a serial `reboot` empties RAM, then session B reads with no
keys injected. The transcript must contain
`[MFC] read: sector N opened by a saved key` lines and a `Pages:` count — not
merely "no error".

### Host tests, no hardware

```
./tests/run_native_mfc_tests.sh
```

Covers crypto1, the solver candidate sequence, and the bounded-memory
enumeration.

## 14. Evidence

Local evidence lives in `~/.local/state/cardputer/`, one directory per run. Keys
appear in those logs and are redacted from anything shared.

| Run | What it proves |
|---|---|
| `20261103-195631-519252-test` | first successful key recovery, 3,260 candidates, 180 s |
| `20261103-201400-590341-test` | fresh authentication with the recovered key, full sector read |
| `20261103-192758-202285-test` | read-robustness fix, 4/64 to 24/64 blocks |
| `20261104-090442-279601-test` | reimplemented solver recovers the same key, `Pages: 28` |
| `20261104-092505-114862-test` | sector 5 stall (CDC write blocking) |
| `20261104-100626-149324-test` | sector 6 stall, same cause |
| `20261105-223653-686729-test` | sector 5 recovered by a full 77,312-candidate sweep, `static -> Verified` |
| `20261106-204553-777088-test` | `rfid mfcbench`: per-frame cost model; card refuses auth without a fresh select |
| `20261107-*` | sectors 6 and 7 recovered overnight, `Pages: 36`, then `Pages: 40` |
| `20261108-201231-942796-test` | sector 8 stall in phase `at` at `tried=10524`; keys 6 and 7 saved before it |
| `20261109-*` | sidecar alone opens 9 sectors after reboot: 0 keys injected, `Pages: 40`, `Keys known: 10`, `mfc read done: 40/64 blocks` |

Current state of this card: **40 of 64 blocks readable**. Sectors 0-7, 14, 15
open; 8-13 are locked, of which 8 was verified once in an early RAM-only run and
lost.

## 15. Not verified, or known broken

- **AT-phase hang** in the static sweep (§6). Blocking issue for multi-hour
  unattended runs. The 2026-11-08 run never returned to check `gMfcAbort`.
- **Sector 8-13 keys**: not recovered since the hang. Sector 8 must be re-run
  once the hang is fixed; expected `Pages: 44`.
- **Progress screens** have not been checked against a photo of the panel.
  Copy is verified in code and the serial side, not visually.
- **`rfid recover` with no sector argument** (`recoverAllKeys`): untested.
- **Key B**: never attempted on any sector. Key A is enough to read.
- **Flashing erases saved keys** (LittleFS is inside the image). A backup of the
  key directory before flashing, or an SD card, would fix it.
- **Any other card**: everything here is one MIFARE Classic 1K clone with a
  static PRNG. A normal card would take the nested path, which has never
  succeeded end to end on real hardware.

## 16. Build and flash

```
~/.venv/bin/pio run -e m5stack-cardputer-adv -j 4          # ~90-100 s warm
~/.venv/bin/python3 scripts/cardputer_device.py flash \
    --port /dev/cu.usbmodem101 \
    --image Bruce-m5stack-cardputer-adv.bin \
    --existing-backup ~/.local/state/cardputer/<stamp>-flash/backup-8mb.bin
```

The merged `Bruce-m5stack-cardputer-adv.bin` is flashed at offset `0x0`;
`.pio/build/m5stack-cardputer-adv/firmware.bin` is application-only at
`0x10000`. `flash` takes a full 8 MB backup when one is not supplied and
verifies by reading the image back; `PASS: firmware written and independently
verified against flash` is the line to require. Only one process may hold the
serial port, and the device may come back as a different `usbmodem` number after
a reboot.

Published release with the binary and these scripts:
`cardputer-adv-mfc-2026-11-09` on `dzianisv/firmware`.

## 17. Rules this project learned the hard way

1. Read the vendored function before calling it. Never infer behaviour from a
   name. The RFAL fork is patched and differs from upstream documentation.
2. Every primitive returns a reason, not a boolean. A step code turns one flash
   cycle into five answers.
3. Assert the positive signal. `Static result: Verified`, not "no error
   appeared". The harness used to score `New keys recovered: 0` as a pass, which
   hid a real failure.
4. Measure before optimizing. One instrumented build replaced a 3.6-hour guess
   with a 3x fix.
5. Exact frame lengths, taken from measurement, not theory. A guessed `144`
   broke reads until it was measured as `162`.
6. A record that "works" only in the lucky case is not working. Sector 1's key
   arrived at candidate 3,260 of 66,000; everything past that point was never
   exercised until it failed.
7. Persistence must be proven across a reboot with nothing injected. Loading a
   file that the read path never opens looks identical to working persistence
   until you reboot.
