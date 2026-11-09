# MIFARE Classic recovery: device test scripts

These drive a real M5Stack Cardputer ADV over USB serial. Nothing here writes to
a card: every command authenticates or reads.

| Script | Purpose | Cost |
|---|---|---|
| `run-persist-test.sh` | read → reboot → read, proving saved keys are used without a sweep | ~3 min |
| `run-fullcard-sweep.sh` | recover every locked sector, then read the card | ~60-80 min per sector |

Both wrap `scripts/cardputer_device.py`, which flashes, verifies, and scores each
serial command with a positive matcher rather than "no error appeared".

## Before you start

```
python3 -m venv ~/.venv && ~/.venv/bin/pip install pyserial esptool
```

A backup of the whole 8 MB flash is taken by the flash step; keep it, the
firmware cannot recover a wiped NVS or bootloader without it.

## Keys stay local

`KNOWN_KEYS_FILE` / `EXTRA_KEYS_FILE` are optional files of previously recovered
keys, one per line:

```
Key A sector 5: EE B4 20 20 9D 0C
```

They are read, never printed, and never committed. On the device the keys live in
`/BruceRFID/mfc_keys/<UID>.txt`; `rfid mfckeys show` lists sectors and never a
key value, so transcripts are safe to share.
