# Plan: on-device MIFARE Classic read + key recovery (UI/UX)

Status: implemented, awaiting flash + hardware test (2026-11-07)
Scope: M5Stack Cardputer ADV + ST25R3916 over I2C. Nothing here writes to the
card being examined.

## Intended user flow

```
RFID -> Read + recover
  1. read the card
       "Sectors: 16  locked: 8  Keys known: 3"
       "~62 min per locked sector, ~8 h 17 m total"
       "[OK] start   [ESC] back"
  2. per locked sector, cheapest algorithm first, showing which one runs:
       1/3 nested auth      seconds, fails instantly on this card (static nonce)
       2/3 static sweep     65k authentications, ~78 min, the one that works here
       3/3 darkside         only after the sweep fails; last because its short
                            transceives fragment the heap the sweep needs
  3. every verified key is written to SD immediately
  4. re-read -> "Pages: 44/64"  (a number, not a claim)
```

The user is asked before anything expensive starts, and can stop after the
current sector. Stopping is never a total loss, because keys are on disk before
the next sector begins.

## What was built

### 1. Key persistence (`ST25R3916`)

- Sidecar `/BruceRFID/mfc_keys/<UID>.txt`, one `A <sector> <12 hex>` /
  `B <sector> <12 hex>` line per verified key.
- Loading happens in `_readMifareClassic()`, because that — not
  `selectMifareClassic()` — is the path a plain "Read tag" takes. The earlier
  version loaded in `selectMifareClassic()` and would never have fired on a
  normal read.
- Saved keys are parsed into a per-sector table (`_mfcSideKeyA/B`). The read
  tries the one key that fits the sector before the 55-key dictionary, so a
  saved key costs one authentication, not one per known key. A saved key never
  sets `keyAFound` on its own: the card has to prove it, otherwise the sector
  list and the estimate would lie.
- `mfcKeysSaveAll()` runs after a read that opened anything, and the moment a
  sector verifies during recovery. It merges instead of replacing: a partial
  read must not erase keys that were already proven.
- Missing SD, missing file, malformed line: ignored, never fatal.
- Serial: `rfid mfckeys [save|load|show]`. `show` prints sector and type only,
  never a key value, so keys stay out of logs.

### 2. UI entry `Read + recover` (`TagOMatic::READ_RECOVER_MODE`)

- Sits directly under "Read tag" in the RFID menu, only for ST25R3916.
- Runs the flow above with its own fixed-row progress screen (`sector 3/8
  locked`, algorithm step, candidate count, minutes left).

### 3. Honest progress

- The old screen said "Nested recovery" during the 65k sweep. It now reads the
  driver's live phase: `2/3 static sweep 41200/77312`.
- Darkside publishes its own phase now, so step `3/3 darkside` is real rather
  than showing the previous stage's name.
- The "agree before sweeping" gate captured the keypress. `check()` clears the
  flag it reads, so the previous code would have started a five-hour sweep on an
  ESC press.

## Non-goals

- No writes to the examined card.
- No solver changes; the 78-minute sector is a bus-cost problem (batched I2C
  writes / SPI), tracked separately.
- Block data persistence is unchanged (`.rfid` dump saving).

## Evidence so far (2026-11-07, overnight run)

| Sector | Result | Cost |
|---|---|---|
| 6 | `static -> Verified`, `Pages: 36` | ~62 min |
| 7 | `static -> Verified`, `Pages: 40` | ~62 min |
| 8 | `static -> Verified`, key never printed | ~62 min |
| 9-13 | not reached: USB link dropped at 07:22Z | — |

Keys for 6 and 7 were recovered from the transcript; 8's is gone because the old
firmware kept keys in RAM only. That is exactly the failure this plan fixes.

## Verification still owed

1. Flash, open `Read + recover`, confirm the summary screen and the step label.
2. Let one sector verify, power-cycle, re-read: the sector must open from the
   sidecar with no sweep.
3. Confirm `rfid mfckeys show` reports the sector without printing the key.
