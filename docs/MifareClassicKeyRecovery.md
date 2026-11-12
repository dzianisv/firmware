# MIFARE Classic key recovery on the Cardputer ADV

Status as of 2026-11-09. Hardware is an M5Stack Cardputer ADV (ESP32-S3, no
PSRAM) with an ST25R3916 NFC reader over I2C. Every number here was measured on
that hardware unless the text says otherwise. No key values appear in this file.

## What it does

Open `RFID → Read tag` and put the card on the reader. The firmware reads what
the card allows. If sectors are still locked, the read screen tells you how many
and what a recovery attempt would cost, then waits for you to press OK.

If you press OK, it works through the locked sectors one at a time, trying the
cheapest attack first. A key only counts once a real authentication with it
succeeds. Each verified key is written to a per-card file straight away, so
stopping early or losing power does not throw the work away. At the end the card
is read again and you get a block count.

Nothing in this flow writes to the card. There is no erase, no clone, and no
write command anywhere in the path.

## Where the code is

| What | File |
|---|---|
| Offer screen, progress screen, result screen | `src/modules/rfid/tag_o_matic.cpp` (`offer_mfc_recovery`) |
| One-per-placement state | `src/modules/rfid/tag_o_matic.h` (`_mfcOfferUID`) |
| Menu (deliberately has no entry for this) | `src/core/menu_items/RFIDMenu.cpp` |
| Select, auth, transceive, read | `src/modules/rfid/ST25R3916.cpp` |
| Dump structure and public API | `src/modules/rfid/ST25R3916.h` |
| Attack order | `ST25R3916::recoverSectorKeys` |
| Crypto1 and candidate solver | `src/modules/rfid/crypto1.cpp`, `mfc_flipper.cpp` |
| Earlier bounded-memory solver | `src/modules/rfid/mfc_recovery.cpp` |
| Darkside solver | `src/modules/rfid/mfc_darkside.cpp` |
| Serial commands | `src/core/serial_commands/rfid_commands.cpp` |
| Device test harness | `scripts/cardputer_device.py` |
| Test scripts | `scripts/mfc-test/` |
| Host tests | `tests/run_native_mfc_tests.sh` |

`ST25R_RECOVERY_LOG` is a macro private to `ST25R3916.cpp`. Using it from
`tag_o_matic.cpp` fails to compile, so that file uses `Serial.printf`.

## How a read turns into a recovery

`Read tag` runs the usual read loop. It calls `_rfid->read()`, prints the card
details, and then calls `offer_mfc_recovery()`. That function returns
immediately unless the card is a MIFARE Classic with at least one sector that
has no known key.

```
Read tag
  read the card (dictionary keys plus any keys saved for this UID)
  show UID, SAK, pages
  offer_mfc_recovery()
      nothing locked            -> return, no screen
      already offered this UID  -> return
      otherwise
          "Sectors: 16  locked: 5"
          "Keys known: 10"
          "~62 min per locked sector"
          "~5 h 10 m total"
          "Card is never written to"
          "[OK] recover   [ESC] read only"
              ESC -> back to the read screen
              OK  -> sweep, cheapest attack first, keys saved as they verify
                     then re-read and show "Keys found", "Keys known", "Pages"
```

Three details in there are load-bearing:

- The offer appears once per placement. `read_card()` runs about every two
  seconds while the card sits there, and a prompt that came back each time would
  be a trap.
- Lifting the card clears `_mfcOfferUID`, so the next placement offers again.
- The OK/ESC choice is read once and stored. `check()` clears the key flag it
  reads, so testing `EscPress` again after the wait would always come back false
  and start a five hour sweep on an ESC press.

Pressing ESC during a sweep makes the progress callback return false, which
sets the solver's abort flag. The current sector stops and keys already found
stay saved.

## Which attack runs, and in what order

`recoverSectorKeys(sector)` runs these for each key type still missing:

| Order | Attack | Cost on this card | Starts when |
|---|---|---|---|
| 0 | Reuse a key already in memory | one authentication, about 58 ms | always |
| 1 | Nested authentication | seconds when it works | needs two different nonces |
| 2 | Single-keystream enumeration | 77,312 candidates, 62 to 78 min | nonce distance is 0 |
| 3 | Darkside | open ended | needs a parity oracle |

Nested comes before the enumeration because it costs nothing when it works and
fails in seconds here. The firmware only starts the enumeration after logging
the nested failure (`trying static-nonce (dist=0)`).

Darkside runs last because it sends many short frames that fragment the heap,
and the enumeration that follows then fails to allocate.

The progress screen numbers whichever attack is running, so you can see the
order instead of taking it on faith:

| Driver phase | Screen text | Step |
|---|---|---|
| `nested`, `solve` | `nested auth`, `solving` | 1/3 |
| `sink` | `static sweep` | 2/3 |
| `darkside` | `darkside` | 3/3 |
| `auth1`, `at`, `wupa`, `select`, `halt` | phase name, no step | none |

The locked count on the offer screen is computed from what the read actually
opened, so sectors that a saved key or the dictionary already opened are never
offered.

## Saving keys

A sweep takes hours, and a key that is not written down is wasted work. The dump
file stores blocks, not keys, so keys get their own file per card:

- Path: `/BruceRFID/mfc_keys/<UID>.txt` on SD, or LittleFS when no card is
  mounted. This unit has no SD card, so it uses LittleFS.
- Format: comment lines starting with `#`, then one `A <sector> <12 hex>` or
  `B <sector> <12 hex>` per key.
- Written by `recoverSectorKeys` whenever it finds something, and by a read that
  opened at least one block.
- Read by `_readMifareClassic()`, which is the read path. The first version put
  the load in `selectMifareClassic()`, which a plain read never calls, so
  persistence looked like it did nothing.
- A loaded key is a guess until the card proves it. Loading fills a per-sector
  table and leaves `keyAFound` false, and only a successful authentication marks
  it. Otherwise a card that shares a UID but not the keys would report sectors
  it cannot read.
- Saves merge. `mfcKeysSaveAll()` writes the union of what is proven now and
  what was already in the file, so a read that ends early cannot erase keys.
- `rfid mfckeys show` lists sector and key type only. It never prints a key.
- Flashing the merged image wipes these files, because LittleFS sits inside the
  image. Reboots and power cycles are fine.

The second bug in this area was a line length check. Requiring 17 characters
silently skipped every single-digit sector while loading two-digit ones, which
looked exactly like "persistence mostly works". Both fixes are in `faeece5` and
`041065c`.

## Stalls, and the hang that is still open

Sweeps used to go silent. Sector 5 died at `tries=17920`, sector 6 at
`tries=12032`, with no panic and a stable heap. The cause was `Serial.printf` on
the USB CDC console, which blocks forever once the host stops reading, and the
sweep logs every 256 candidates. Every log site now checks
`Serial.availableForWrite()` first and drops the line instead of blocking
(commit `8b7feaa`).

Above that sits `_mfcMonitorTask`, an independent task pinned to core 0. It
prints a heartbeat every 30 seconds with the live phase, band, bucket, candidate
count and free heap. It treats 10 seconds without a heartbeat as a stall, 30
seconds during the `solve` phase, prints the state once, and sets `gMfcAbort`.

That abort only works where the code comes back to check it. On 2026-11-08 a
sector 8 sweep froze at 10,524 candidates in phase `at`. `tried` sat still for
3.6 hours, the heap stayed at 147,488 bytes, and the monitor kept printing. The
abort flag was set and never observed because the sweep was stuck inside the
transceive path. The wrapper around a frame is bounded at 25 ms, so the freeze
is below it, in the vendor driver or the I2C layer. Until that is sorted out, an
unattended multi-hour run is not safe on this card.

## The card this was built against

MIFARE Classic 1K clone, UID `1F 47 B5 D9`, SAK `08`, ATQA `04 00`.

Its PRNG is static. Every authentication returns the nonce `01200145`, for every
block, in every session. That one property decides which attacks can work.

Sectors 0 and 2 use the default key `A0A1A2A3A4A5`. Sectors 3, 4, 14 and 15 use
`FFFFFFFFFFFF`. Sectors 1, 5, 6 and 7 were recovered on device and live in the
sidecar file.

## Which attacks work on it

| Attack | What it needs | Result here |
|---|---|---|
| Nested | two different nonces from the same stream | impossible, the nonce never changes |
| Darkside | a tag that NAKs corrupted parity | dead after 419 probes |
| Dictionary | nothing | works, 6 default-key sectors |
| Single-sample enumeration | one known key and one captured nonce under the target key | works, sector 1 in 180 s |

Because the nonce is fixed, the plaintext is known, so one captured encrypted
nonce gives 32 bits of keystream. That narrows the key to roughly 66,000 to
77,312 candidates, and each one is checked with a real authentication, so a
wrong candidate cannot survive.

Two approaches were tried and dropped. An offline 32-bit half-key oracle ran 480
shaped probes and found nothing; the lines that looked like partial hits were
4-bit NAKs being parsed as 36-bit frames. Card emulation (mfkey32) needs a second
reader that already knows the key, and there is only one reader.

## What a candidate costs

Every candidate talks to the card: wake it, select it, try a key. That exchange
sets the pace.

| Step | Measured |
|---|---|
| Wake and select (WUPA + SELECT) | 23.3 ms |
| One authentication attempt | 24.0 ms |
| Candidates per second | 17 to 18 |
| Full 77,312-candidate sweep | 62 to 78 minutes |
| Dictionary pass before the crypto stage | about 15 minutes |

`rfid mfcbench` breaks a frame down so the numbers can be checked instead of
guessed:

| Measurement | Value | Reading |
|---|---|---|
| One polled IRQ register read | 400 us | about 200 us per I2C transaction, near wire time at 400 kHz |
| Frame the card ignores, 3 ms timeout | 13.0 ms | |
| Same frame, 10 ms timeout | 20.1 ms | slope is 7 ms, so the wait honours the timeout |
| Fixed cost per frame | 10.0 ms | everything except waiting for the card |
| of which `rfalStartTransceive` | 2.8 ms | chip setup before the frame |
| of which first `rfalWorker()` | 5.5 ms | more setup, transmit, TXE wait |
| of which timeout polling | 3.0 ms | 15 iterations at about 320 us |

A frame is about 10 ms of reader work plus 1.5 ms of air, and a candidate needs
four frames, so roughly 48 ms. Two things follow.

The card sets the pace. After a wrong-key NAK it answers nothing for 29 of 30
back-to-back authentications, so every candidate needs a fresh select. WUPA and
SELECT cannot be skipped.

The 10 ms is I2C traffic rather than radio. The driver re-writes the same
registers before every frame over a 400 kHz bus with no interrupt line. A leaner
transceive path could cut it, but the working path already recovers a sector in
about an hour, and rewriting the transmit side risks the one thing that works.

Earlier these numbers were 67.8 and 66.3 ms per step, about 5 candidates a
second, because the I2C bus defaulted to 100 kHz. At 400 kHz, the ST25R3916
fast-mode limit, cost per step fell by two thirds.

## Why the solver was rewritten

The first solver asked the heap for one contiguous 98 KiB block. After a read
the heap is fragmented and that request fails, which showed up as
`static -> NoMemory` in the middle of a recovery. Reserving the block at startup
fixed it but held 98 KiB for the whole session, dropping free memory from about
160 KiB to 62 KiB.

The replacement copies the memory shape from Flipper's MFKey app: candidates
packed into 24-bit states, the sweep split into MSB buckets, many small fixed
allocations instead of one large one. On host it peaks at 53,248 bytes with a
largest single allocation of 5,120 bytes across 18 allocations. Free heap on the
device during recovery is 143,884 bytes. The host test asserts the new solver
emits the same candidate sequence as the old one, so the rewrite changed layout
only.

## Hardware facts worth keeping

- Frame lengths, measured over thousands of exchanges: plain nonce 36 bits,
  encrypted nonce 36 bits, authentication answer 36 bits or a 4-bit NAK, block
  read 162 bits. The code checks these exact values rather than `>=`.
- An early check used 144 for a block read, which is 18 bytes with no parity,
  and reads returned `Pages: 0`. 162 is correct: 16 data bytes, 2 CRC bytes and
  18 parity bits all arrive.
- One missed reselect used to abandon a whole sector. The read path now retries
  with `_mfcReacquire(1500, 2)` and retries the sector once, which took a read
  from 4 of 64 blocks to 24 of 64.
- The clone stops answering a bare authentication after a failed attempt, so
  every miss needs a fresh anticollision.
- There is no PSRAM. Solver scratch comes from the internal heap, and the shape
  of the allocations matters as much as their total size.
- The reader sometimes misses its boot-time I2C probe on the first boot after a
  flash and reports `No I2C devices found`. Power-cycle once. It is not a flash
  failure.

## Serial commands

All of these authenticate or read. None of them write to the card.

```
rfid read [ms]                                   read the card and print pages
rfid recover <ms> <sector>                       full path for one sector
rfid recover <ms>                                all sectors (untested)
rfid mfcstatic <knownBlk> A <key> <targetBlk> A  single-keystream recovery
rfid mfckey <block> A <12-hex>                   verify one key, PASS or FAIL
rfid mfcaddkey <12-hex>                          load a key for the next read
rfid mfckeys [save|load|show]                    per-card key file
rfid mfcdarkside <blk> A                         darkside attempt
rfid mfcbench [okBlk] [nakBlk]                   per-frame timings
rfid mfcmeasure                                  raw frame timing samples
rfid mfcscan                                     look for cards
rfid mfcsample <blk>                             capture one nonce sample
rfid mfcwire                                     wiring and register check
rfid mfcdiag                                     reader diagnostics
```

The device UI does the same thing as `rfid recover` without a serial host
attached.

## Testing

### Device harness

`scripts/cardputer_device.py` has three actions: `flash` writes a merged image
at offset 0 and verifies it by reading it back, `test` runs boot checks plus any
RFID commands you pass, and `probe` reports what the reader says.

Useful flags are `--port`, `--image`, `--existing-backup <8mb.bin>`, `--rfid`,
`--require-tag`, `--skip-read`, `--rfid-command "<cmd>"` (repeatable),
`--command-timeout`, `--recover`, `--recover-sector` and `--recover-timeout`.

Commands are scored on positive output, never on the absence of an error:

| Command | Counts as PASS only when the output has |
|---|---|
| `rfid mfckey` | `: PASS` |
| `rfid mfcstatic` | `Static result: Verified` |
| `rfid mfcdarkside` | `Darkside result: Verified` or `AlreadyKnown` |
| `rfid read` | `Pages: N` with N above zero |
| `rfid recover` | `New keys recovered: N` with N above zero |
| anything else | some output, no `ERROR`, `FAIL` or `failed` |

A missing tag is recorded as `BLOCKED`, never as a pass. Runs land in
`~/.local/state/cardputer/<stamp>-<action>/`, and `serial-transcript.log` is the
file to read when the score and the transcript disagree.

`rfid mfckeys show` is the one rough edge: it falls through to the generic
matcher and can print FAIL while the transcript is fine, because it prints
sector numbers and no error. `New keys recovered: 0` is a real FAIL by design,
and a sector whose key was already in the sidecar produces exactly that, so
judge a sweep by the `static -> Verified` lines and the `Pages` count.

### Test scripts

```
PORT=/dev/cu.usbmodem101 scripts/mfc-test/run-persist-test.sh
PORT=/dev/cu.usbmodem101 SECTORS="8 9 10" scripts/mfc-test/run-fullcard-sweep.sh
```

The first takes about three minutes and proves persistence: session A reads the
card and writes the sidecar, a serial `reboot` empties RAM, session B reads again
with no keys injected. The transcript must show
`[MFC] read: sector N opened by a saved key` lines and a `Pages` count.

The second sweeps the sectors you name and saves each key as it verifies.

Environment: `PORT`, `STATE_DIR` (defaults to `~/.local/state/cardputer`),
`SECTORS`, `TIMEOUT` (default 10800 seconds), `LONG=1` to keep going past a
failed sector, and `KNOWN_KEYS_FILE` or `EXTRA_KEYS_FILE` pointing at a local
file of `Key A sector <n>: AA BB CC DD EE FF` lines. That file is read, never
printed, and never committed.

### Host tests

```
./tests/run_native_mfc_tests.sh
```

Covers crypto1, the solver's candidate sequence, and the bounded-memory
enumeration. No hardware needed.

## Evidence

Local runs live in `~/.local/state/cardputer/`, one directory per run. Keys
appear in those logs and are redacted from anything shared.

| Run | What it shows |
|---|---|
| `20261103-195631-519252-test` | first recovery, 3,260 candidates, 180 s |
| `20261103-201400-590341-test` | fresh authentication with the recovered key, full sector read |
| `20261103-192758-202285-test` | read fix, 4/64 blocks to 24/64 |
| `20261104-090442-279601-test` | rewritten solver finds the same key, `Pages: 28` |
| `20261104-092505-114862-test` | sector 5 stall from the blocking CDC write |
| `20261104-100626-149324-test` | sector 6 stall, same cause |
| `20261105-223653-686729-test` | sector 5 recovered by a full 77,312-candidate sweep |
| `20261106-204553-777088-test` | `rfid mfcbench` cost model, and the card refusing auth without a fresh select |
| 2026-11-07 runs | sectors 6 and 7 recovered overnight, `Pages: 36` then `Pages: 40` |
| `20261108-201231-942796-test` | sector 8 hang at `tried=10524` in phase `at`, keys 6 and 7 already saved |
| 2026-11-09 runs | sidecar alone opens 9 sectors after reboot: no keys injected, `Pages: 40`, `Keys known: 10` |

The card is currently at 40 of 64 blocks readable. Sectors 0 to 7, 14 and 15
open. Sectors 8 to 13 are locked; sector 8 was recovered once in an early
RAM-only build and that key was lost.

## What is not done

- The AT-phase hang described above. It blocks long unattended runs.
- Sectors 8 to 13. Sector 8 needs re-running once the hang is fixed; that should
  take the card to `Pages: 44`.
- The progress screens have not been checked against a photo of the panel. The
  text is verified in code and in the serial log, not by eye.
- `rfid recover` with no sector argument is untested.
- Key B has never been attempted on any sector. Key A is enough to read.
- Flashing wipes saved keys. An SD card or a copy of the key file before
  flashing would fix that.
- Everything here is one MIFARE Classic 1K clone with a static PRNG. A normal
  card would take the nested path, which has never succeeded on real hardware.

## Build and flash

```
~/.venv/bin/pio run -e m5stack-cardputer-adv -j 4
~/.venv/bin/python3 scripts/cardputer_device.py flash \
    --port /dev/cu.usbmodem101 \
    --image Bruce-m5stack-cardputer-adv.bin \
    --existing-backup ~/.local/state/cardputer/<stamp>-flash/backup-8mb.bin
```

The merged `Bruce-m5stack-cardputer-adv.bin` goes at offset `0x0`.
`.pio/build/m5stack-cardputer-adv/firmware.bin` is application-only at `0x10000`
and will not boot on its own. `flash` takes a full 8 MB backup when you do not
supply one and verifies by reading the image back; require
`PASS: firmware written and independently verified against flash`. Only one
process can hold the serial port, and the device can come back as a different
`usbmodem` number after a reboot.

A build with the binary and these scripts is published as
`cardputer-adv-mfc-2026-11-09` on `dzianisv/firmware`.

## Lessons that cost us time

1. Read the vendored function before calling it. The RFAL fork is patched and
   does not behave like the upstream documentation. Guessing from a function
   name cost a full day.
2. Return a reason, not a boolean. A step code turns one flash cycle into five
   answers.
3. Assert the positive signal. The harness once scored `New keys recovered: 0`
   as a pass and hid a real failure for a day.
4. Measure before optimizing. One instrumented build replaced a 3.6-hour guess
   with a threefold fix.
5. Take frame lengths from measurement. A guessed 144 broke reads until it was
   measured as 162.
6. A path that works only in the lucky case is not working. Sector 1's key
   arrived at candidate 3,260 of 66,000, and nothing past that point had ever
   been exercised until it failed.
7. Prove persistence across a reboot with nothing injected. Loading a file that
   the read path never opens looks identical to working persistence until you
   reboot.
