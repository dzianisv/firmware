#include "rfid_commands.h"
#if !defined(LITE_VERSION)
#include "modules/rfid/ST25R3916.h"
#endif
#include "core/sd_functions.h"
#include "modules/rfid/PN532.h"
#include "modules/rfid/RFID2.h"
#include "modules/rfid/RFIDInterface.h"
#include <globals.h>

// Common workflows via serial:
//   Read a tag:                    rfid read [timeout=5000]
//   Recover unknown MFC keys:      rfid recover [timeout=5000] [sector]
//   Emulate NDEF over ISO14443-4:  rfid emulate t4t [url|text <value>]
//   Emulate over FeliCa:           rfid emulate felica
//   Emulate from a saved file:     rfid loadfile [filepath] -> rfid emulate [t4t|felica]
//   Write NDEF to a tag:           rfid ndef [url|text] [value]
//   Write to a tag from a file:    rfid loadfile [filepath] -> rfid write [timeout=5000]

static RFIDInterface *_rfid = nullptr;

static RFIDInterface *_createRfidModule() {
    switch (bruceConfigPins.rfidModule) {
        case PN532_I2C_MODULE: return new PN532(PN532::CONNECTION_TYPE::I2C);
#ifdef M5STICK
        case PN532_I2C_SPI_MODULE: return new PN532(PN532::CONNECTION_TYPE::I2C_SPI);
#endif
        case PN532_SPI_MODULE: return new PN532(PN532::CONNECTION_TYPE::SPI);
        case RC522_SPI_MODULE: return new RFID2(false);
#if !defined(LITE_VERSION)
        case ST25R3916_SPI_MODULE: return new ST25R3916(ST25R3916::SPI_MODE);
        case ST25R3916_I2C_MODULE: return new ST25R3916(ST25R3916::I2C_MODE);
#endif
        case M5_RFID2_MODULE:
        default: return new RFID2();
    }
}

static bool _ensureRfid() {
    if (_rfid != nullptr) return true;
    _rfid = _createRfidModule();
    if (!_rfid->begin()) {
        delete _rfid;
        _rfid = nullptr;
        serialDevice->println("ERROR: RFID module not found");
        return false;
    }
    return true;
}

static uint32_t _argTimeout(Command &cmd, uint32_t fallback = 5000) {
    String timeoutStr = cmd.getArgument("timeout").getValue();
    uint32_t timeout_ms = (uint32_t)timeoutStr.toInt();
    return timeout_ms == 0 ? fallback : timeout_ms;
}

static int _readTagWithTimeout(uint32_t timeout_ms) {
    serialDevice->println("Waiting for tag (" + String(timeout_ms) + " ms)...");

    uint32_t deadline = millis() + timeout_ms;
    int result = RFIDInterface::TAG_NOT_PRESENT;

    while (millis() < deadline) {
        result = _rfid->read();
        if (result == RFIDInterface::SUCCESS) break;
        if (result == RFIDInterface::FAILURE) break;
        delay(50);
    }

    return result;
}

static void _printTagInfo() {
    serialDevice->println("UID:   " + _rfid->printableUID.uid);
    serialDevice->println("Type:  " + _rfid->printableUID.picc_type);
    serialDevice->println("SAK:   " + _rfid->printableUID.sak);
    serialDevice->println("ATQA:  " + _rfid->printableUID.atqa);
    serialDevice->println("Pages: " + String(_rfid->dataPages));
    if (_rfid->totalPages > 0 && _rfid->totalPages != _rfid->dataPages) {
        serialDevice->println("Total pages: " + String(_rfid->totalPages));
    }
    if (_rfid->strAllPages.length() > 0) {
        serialDevice->println("--- data ---");
        serialDevice->print(_rfid->strAllPages);
        serialDevice->println("------------");
    }
}

// rfid read [timeout=5000]
uint32_t rfidReadCallback(cmd *c) {
    Command cmd(c);
    uint32_t timeout_ms = _argTimeout(cmd);

    if (!_ensureRfid()) return false;

    int result = _readTagWithTimeout(timeout_ms);
    if (result != RFIDInterface::SUCCESS) {
        if (_rfid->printableUID.uid.length() > 0) _printTagInfo();
        serialDevice->println("Read failed: " + _rfid->statusMessage(result));
        return false;
    }

    _printTagInfo();
    return true;
}

// rfid write [timeout=5000]
uint32_t rfidWriteCallback(cmd *c) {
    Command cmd(c);
    uint32_t timeout_ms = _argTimeout(cmd);

    if (!_ensureRfid()) return false;
    if (_rfid->strAllPages.length() == 0) {
        serialDevice->println("No data to write. Run 'rfid read' first.");
        return false;
    }

    serialDevice->println("Place target tag on reader...");
    delay(timeout_ms > 3000 ? 2000 : 500);

    int result = _rfid->write();
    serialDevice->println("Write: " + _rfid->statusMessage(result));
    return result == RFIDInterface::SUCCESS;
}

// rfid clone [timeout=5000]
uint32_t rfidCloneCallback(cmd *c) {
    Command cmd(c);
    uint32_t timeout_ms = _argTimeout(cmd);

    if (!_ensureRfid()) return false;
    if (_rfid->printableUID.uid.length() == 0) {
        serialDevice->println("No UID loaded. Run 'rfid read' first.");
        return false;
    }

    serialDevice->println("Cloning UID: " + _rfid->printableUID.uid);
    serialDevice->println("Place Magic card on reader...");
    delay(timeout_ms > 3000 ? 2000 : 500);

    int result = _rfid->clone();
    serialDevice->println("Clone: " + _rfid->statusMessage(result));
    return result == RFIDInterface::SUCCESS;
}

// rfid emulate [t4t|felica] [value]
uint32_t rfidEmulateCallback(cmd *c) {
    Command cmd(c);
    String mode = cmd.countArgs() > 0 ? cmd.getArgument(0).getValue() : String("");
    mode.toLowerCase();

    if (!_ensureRfid()) return false;

    _rfid->emuMode = "";
    if (mode == "t4t" || mode == "felica") {
        _rfid->emuMode = mode;
        // For T4T allow an inline NDEF (URL by default, or "text <value>").
        if (mode == "t4t") {
            String type = "url";
            String value = "";
            int start = 1;
            if (cmd.countArgs() > 1) {
                String a1 = cmd.getArgument(1).getValue();
                String a1l = a1;
                a1l.toLowerCase();
                if (a1l == "text" || a1l == "url") {
                    type = a1l;
                    start = 2;
                }
            }
            for (int i = start; i < cmd.countArgs(); i++) {
                if (value.length() > 0) value += " ";
                value += cmd.getArgument(i).getValue();
            }
            if (value.length() > 0) { _rfid->buildNdefMessage(type, value); }
        }
    }

    if (_rfid->printableUID.uid.length() > 0) {
        serialDevice->println(
            "Emulating UID: " + _rfid->printableUID.uid + " (" + _rfid->printableUID.picc_type + ")"
        );
    }
    String caveat = _rfid->emulationCaveat();
    if (caveat.length() > 0) serialDevice->println("[!] " + caveat);
    serialDevice->println(
        "Starting RFID emulation" + (mode.length() ? (" (" + mode + ")") : String("")) + "..."
    );
    // backToMenu() (run after every serial command) leaves this flag set, which
    // would make emulate()'s loop bail out on its very first iteration.
    returnToMenu = false;
    int result = _rfid->emulate();
    serialDevice->println("Emulate: " + _rfid->statusMessage(result));
    return result == RFIDInterface::SUCCESS;
}

// rfid erase
uint32_t rfidEraseCallback(cmd *c) {
    if (!_ensureRfid()) return false;

    serialDevice->println("Place tag on reader to erase...");
    int result = _rfid->erase();
    serialDevice->println("Erase: " + _rfid->statusMessage(result));
    return result == RFIDInterface::SUCCESS;
}

// rfid info
uint32_t rfidInfoCallback(cmd *c) {
    if (!_rfid || _rfid->printableUID.uid.length() == 0) {
        serialDevice->println("No tag data. Run 'rfid read' first.");
        return false;
    }
    _printTagInfo();
    return true;
}

// rfid reset  — destroys the module instance (forces re-init on next command)
// rfid save [filename=rfid_dump] [format=bruce|flipper]
uint32_t rfidSaveCallback(cmd *c) {
    Command cmd(c);
    String filename = cmd.getArgument("filename").getValue();
    if (filename.length() == 0) filename = "rfid_dump";
    String format = cmd.getArgument("format").getValue();
    format.toLowerCase();

    if (!_ensureRfid()) return false;
    if (_rfid->printableUID.uid.length() == 0) {
        serialDevice->println("No tag data. Run 'rfid read' first.");
        return false;
    }

    int result;
    if (format == "flipper") {
        result = _rfid->saveFlipper(filename);
        if (result == RFIDInterface::NOT_IMPLEMENTED)
            serialDevice->println("Flipper format not supported by this module; using Bruce format.");
    } else {
        result = _rfid->save(filename);
    }
    serialDevice->println("Save: " + _rfid->statusMessage(result));
    return result == RFIDInterface::SUCCESS;
}

// rfid loadfile [filepath=/BruceRFID/rfid_dump.rfid]
uint32_t rfidLoadFileCallback(cmd *c) {
    Command cmd(c);
    String filepath = cmd.getArgument("filepath").getValue();
    if (filepath.length() == 0) filepath = "/BruceRFID/rfid_dump.rfid";

    if (!_ensureRfid()) return false;

    // loadFromFile() lives in the driver (or, by default, in RFIDInterface), so
    // the serial command and the GUI 'Load file' share one implementation and
    // never diverge in behavior.
    int loaded = _rfid->loadFromFile(filepath);
    serialDevice->println("Load: " + _rfid->statusMessage(loaded));
    if (loaded == RFIDInterface::SUCCESS) _printTagInfo();
    return loaded == RFIDInterface::SUCCESS;
}

// rfid ndef [url|text] [value]
uint32_t rfidNdefCallback(cmd *c) {
    Command cmd(c);
    String type = cmd.countArgs() > 0 ? cmd.getArgument(0).getValue() : String("url");
    String value = "";
    for (int i = 1; i < cmd.countArgs(); i++) {
        if (value.length() > 0) value += " ";
        value += cmd.getArgument(i).getValue();
    }
    type.toLowerCase();
    if (value.length() == 0) value = (type == "text") ? "Bruce" : "https://bruce.computer";

    if (!_ensureRfid()) return false;

    _rfid->buildNdefMessage(type, value);

    int result = _rfid->write_ndef();
    serialDevice->println("NDEF: " + _rfid->statusMessage(result));
    return result == RFIDInterface::SUCCESS;
}

uint32_t rfidResetCallback(cmd *c) {
    if (_rfid) {
        delete _rfid;
        _rfid = nullptr;
        serialDevice->println("RFID module reset.");
    } else {
        serialDevice->println("No active RFID module.");
    }
    return true;
}

// rfid autotest [mode=read-write] [timeout=5000]
uint32_t rfidAutotestCallback(cmd *c) {
    Command cmd(c);
    String mode = cmd.getArgument("mode").getValue();
    mode.toLowerCase();
    uint32_t timeout_ms = _argTimeout(cmd);

    if (!_ensureRfid()) return false;

    serialDevice->println("RFID autotest mode: " + mode);

    if (mode == "read") {
        int result = _readTagWithTimeout(timeout_ms);
        serialDevice->println("Read: " + _rfid->statusMessage(result));
        if (result == RFIDInterface::SUCCESS) _printTagInfo();
        return result == RFIDInterface::SUCCESS;
    }

    if (mode == "write") {
        int result = _rfid->write();
        serialDevice->println("Write: " + _rfid->statusMessage(result));
        return result == RFIDInterface::SUCCESS;
    }

    if (mode == "read-write") {
        int readResult = _readTagWithTimeout(timeout_ms);
        serialDevice->println("Read: " + _rfid->statusMessage(readResult));
        if (readResult != RFIDInterface::SUCCESS) return false;

        String savedPages = _rfid->strAllPages;
        _printTagInfo();
        serialDevice->println("Writing the captured dump back to the current tag...");
        int writeResult = _rfid->write();
        _rfid->strAllPages = savedPages;
        serialDevice->println("Write: " + _rfid->statusMessage(writeResult));
        return writeResult == RFIDInterface::SUCCESS;
    }

    if (mode == "clone") {
        int result = _rfid->clone();
        serialDevice->println("Clone: " + _rfid->statusMessage(result));
        return result == RFIDInterface::SUCCESS;
    }

    // MIFARE Classic: dict-attack dump (uses the normal read path, which
    // dispatches to the Crypto1 reader when the SAK is a MIFARE Classic SAK).
    if (mode == "mfc") {
        int result = _readTagWithTimeout(timeout_ms);
        serialDevice->println("MFC read: " + _rfid->statusMessage(result));
        if (result == RFIDInterface::SUCCESS) _printTagInfo();
        return result == RFIDInterface::SUCCESS;
    }

    if (mode == "mfc-write") {
        int result = _rfid->write();
        serialDevice->println("MFC write: " + _rfid->statusMessage(result));
        return result == RFIDInterface::SUCCESS;
    }

    if (mode == "mfc-clone") {
        int result = _rfid->clone();
        serialDevice->println("MFC clone: " + _rfid->statusMessage(result));
        return result == RFIDInterface::SUCCESS;
    }

    if (mode == "emulate") {
        if (_rfid->printableUID.uid.length() > 0) {
            serialDevice->println(
                "Emulating UID: " + _rfid->printableUID.uid + " (" + _rfid->printableUID.picc_type + ")"
            );
        }
        String caveat = _rfid->emulationCaveat();
        if (caveat.length() > 0) serialDevice->println("[!] " + caveat);
        // backToMenu() (run after every serial command) leaves this flag set, which
        // would make emulate()'s loop bail out on its very first iteration.
        returnToMenu = false;
        int result = _rfid->emulate();
        serialDevice->println("Emulate: " + _rfid->statusMessage(result));
        return result == RFIDInterface::SUCCESS;
    }

    serialDevice->println(
        "Invalid mode. Use: read, write, read-write, clone, emulate, mfc, mfc-write, mfc-clone"
    );
    return false;
}

#if !defined(LITE_VERSION)
// rfid recover [timeout=5000] [sector]
// Read-only: dictionary scan, darkside bootstrap if no key is known, then nested
// recovery. With a sector argument only that sector is attacked.
uint32_t rfidRecoverCallback(cmd *c) {
    Command cmd(c);
    uint32_t timeout_ms = _argTimeout(cmd);

    if (!_ensureRfid()) return false;
    if (bruceConfigPins.rfidModule != ST25R3916_SPI_MODULE &&
        bruceConfigPins.rfidModule != ST25R3916_I2C_MODULE) {
        serialDevice->println("ERROR: recovery requires the ST25R3916 module");
        return false;
    }

    ST25R3916 *st25r = static_cast<ST25R3916 *>(_rfid);
    int result = _readTagWithTimeout(timeout_ms);
    const bool partialMfc = result == RFIDInterface::FAILURE && st25r->mfcDump.sectors > 0;
    if (result != RFIDInterface::SUCCESS && !partialMfc) {
        serialDevice->println("Read failed: " + _rfid->statusMessage(result));
        return false;
    }
    if (partialMfc) {
        serialDevice->println("MIFARE Classic detected but no block readable; trying darkside.");
    }
    serialDevice->println("UID:  " + _rfid->printableUID.uid);
    serialDevice->println("Type: " + _rfid->printableUID.picc_type);

    if (st25r->mfcDump.sectors == 0) {
        serialDevice->println("Not a MIFARE Classic card.");
        return false;
    }

    int bootSec = -1;
    bool bootB = false;
    for (uint8_t s = 0; s < st25r->mfcDump.sectors; s++) {
        if (st25r->mfcDump.keyAFound[s]) {
            bootSec = s;
            bootB = false;
            break;
        }
        if (st25r->mfcDump.keyBFound[s]) {
            bootSec = s;
            bootB = true;
            break;
        }
    }
    if (bootSec < 0) {
        serialDevice->println("No known key in dump; running darkside bootstrap on sector 0.");
    } else {
        serialDevice->println(
            "Bootstrap sector: " + String(bootSec) + " Key " + (bootB ? "B" : "A")
        );
    }

    auto progress = [](unsigned done, unsigned total, void *) {
        static unsigned last = 0;
        if (done != last && (done & 0x1F) == 0) {
            last = done;
            serialDevice->println("Recovering: " + String(done) + "/" + String(total));
        }
        if (serialDevice->available() && serialDevice->read() == 'q') {
            serialDevice->println("Recovery cancelled by serial input.");
            return false;
        }
        delay(1);
        return true;
    };

    const String sectorValue = cmd.getArgument("sector").getValue();
    const bool oneSector = sectorValue.length() > 0 && sectorValue.toInt() >= 0;
    const int recovered = oneSector
                              ? st25r->recoverSectorKeys((uint8_t)sectorValue.toInt(), progress, nullptr)
                              : st25r->recoverAllKeys(progress, nullptr);

    if (recovered == -2) {
        serialDevice->println("Recovery cancelled.");
    } else if (recovered == -3) {
        serialDevice->println("Recovery stopped: low memory.");
    } else if (recovered == -4) {
        serialDevice->println("Recovery stopped: card lost, unsupported, or auth failed.");
    } else if (recovered < 0) {
        serialDevice->println("Recovery unavailable.");
    } else {
        serialDevice->println("New keys recovered: " + String(recovered));
    }

    for (uint8_t s = 0; s < st25r->mfcDump.sectors; s++) {
        for (int useB = 0; useB <= 1; useB++) {
            const bool found = useB ? st25r->mfcDump.keyBFound[s] : st25r->mfcDump.keyAFound[s];
            if (!found) continue;
            const uint8_t *key = useB ? st25r->mfcDump.keyB[s] : st25r->mfcDump.keyA[s];
            String hex;
            char buf[3];
            for (int i = 0; i < 6; i++) {
                snprintf(buf, sizeof(buf), "%02X", key[i]);
                hex += buf;
            }
            serialDevice->println(
                "Sector " + String(s) + " Key " + (useB ? "B" : "A") + ": " + hex
            );
        }
    }

    if (recovered > 0) {
        // Prove the recovered keys: a fresh read re-authenticates with them and
        // must now return more pages than the dictionary-only pass.
        serialDevice->println("Re-reading with recovered keys...");
        const int again = _readTagWithTimeout(timeout_ms);
        if (again == RFIDInterface::SUCCESS) {
            _printTagInfo();
        } else {
            serialDevice->println("Re-read failed: " + _rfid->statusMessage(again));
        }
    }
    return recovered >= 0;
}

// rfid mfckey <block> <A|B> <12-hex-key>
// Read-only single-key test. Prints PASS/FAIL only, never the key.
uint32_t rfidMfcKeyCallback(cmd *c) {
    Command cmd(c);
    if (cmd.countArgs() < 3) {
        serialDevice->println("Usage: rfid mfckey <block> <A|B> <12-hex-key>");
        return false;
    }
    const int block = cmd.getArgument(0).getValue().toInt();
    const String keyType = cmd.getArgument(1).getValue();
    String hex = cmd.getArgument(2).getValue();
    hex.trim();
    hex.replace(" ", "");
    if (block < 0 || block > 255 || hex.length() != 12) {
        serialDevice->println("ERROR: block 0-255 and a 12-hex-character key are required");
        return false;
    }
    uint8_t key[6];
    for (int i = 0; i < 6; i++) {
        key[i] = (uint8_t)strtoul(hex.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
    }
    if (!_ensureRfid()) return false;
    if (bruceConfigPins.rfidModule != ST25R3916_SPI_MODULE &&
        bruceConfigPins.rfidModule != ST25R3916_I2C_MODULE) {
        serialDevice->println("ERROR: key test requires the ST25R3916 module");
        return false;
    }
    ST25R3916 *st25r = static_cast<ST25R3916 *>(_rfid);
    serialDevice->println("Place tag on reader...");
    if (!st25r->selectMifareClassic(5000, true)) {
        serialDevice->println("Read failed: tag not found");
        return false;
    }
    const bool useB = keyType.equalsIgnoreCase("B");
    const bool ok = st25r->mfcAuthTest((uint8_t)block, key, useB);
    serialDevice->println(
        String("Key ") + (useB ? "B" : "A") + " block " + String(block) + ": " +
        (ok ? "PASS" : "FAIL")
    );
    return ok;
}

// rfid mfcmeasure <block> <A|B> <12-hex-key>
// Read-only PRNG probe. One session, repeated nested auths, prints nonces.
uint32_t rfidMfcMeasureCallback(cmd *c) {
    Command cmd(c);
    if (cmd.countArgs() < 3) {
        serialDevice->println("Usage: rfid mfcmeasure <block> <A|B> <12-hex-key>");
        return false;
    }
    const int block = cmd.getArgument(0).getValue().toInt();
    const String keyType = cmd.getArgument(1).getValue();
    String hex = cmd.getArgument(2).getValue();
    hex.trim();
    hex.replace(" ", "");
    if (block < 0 || block > 255 || hex.length() != 12) {
        serialDevice->println("ERROR: block 0-255 and a 12-hex-character key are required");
        return false;
    }
    uint8_t key[6];
    for (int i = 0; i < 6; i++) {
        key[i] = (uint8_t)strtoul(hex.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
    }
    if (!_ensureRfid()) return false;
    if (bruceConfigPins.rfidModule != ST25R3916_SPI_MODULE &&
        bruceConfigPins.rfidModule != ST25R3916_I2C_MODULE) {
        serialDevice->println("ERROR: PRNG probe requires the ST25R3916 module");
        return false;
    }
    ST25R3916 *st25r = static_cast<ST25R3916 *>(_rfid);
    serialDevice->println("Place tag on reader...");
    if (!st25r->selectMifareClassic(5000, true)) {
        serialDevice->println("Read failed: tag not found");
        return false;
    }
    uint32_t dist = 0;
    const auto res = st25r->mfcMeasureDistance(
        (uint8_t)block, key, keyType.equalsIgnoreCase("B"), &dist
    );
    serialDevice->println(String("PRNG result: ") + ST25R3916::recoveryStatus(res));
    serialDevice->println("PRNG step: " + String(dist));
    return res == ST25R3916::RecoveryResult::Verified;
}

// rfid mfcstatic <knownBlock> <A|B> <keyhex> <targetBlock> <A|B>
// Static-nonce key recovery. Read-only: auth attempts only, no writes.
uint32_t rfidMfcStaticCallback(cmd *c) {
    Command cmd(c);
    if (cmd.countArgs() < 5) {
        serialDevice->println(
            "Usage: rfid mfcstatic <knownBlock> <A|B> <12-hex-key> <targetBlock> <A|B>"
        );
        return false;
    }
    const int knownBlock = cmd.getArgument(0).getValue().toInt();
    const String knownType = cmd.getArgument(1).getValue();
    String hex = cmd.getArgument(2).getValue();
    const int targetBlock = cmd.getArgument(3).getValue().toInt();
    const String targetType = cmd.getArgument(4).getValue();
    hex.trim();
    hex.replace(" ", "");
    if (knownBlock < 0 || knownBlock > 255 || targetBlock < 0 || targetBlock > 255 ||
        hex.length() != 12) {
        serialDevice->println("ERROR: blocks 0-255 and a 12-hex-character key are required");
        return false;
    }
    uint8_t key[6];
    for (int i = 0; i < 6; i++) {
        key[i] = (uint8_t)strtoul(hex.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
    }
    if (!_ensureRfid()) return false;
    if (bruceConfigPins.rfidModule != ST25R3916_SPI_MODULE &&
        bruceConfigPins.rfidModule != ST25R3916_I2C_MODULE) {
        serialDevice->println("ERROR: static recovery requires the ST25R3916 module");
        return false;
    }
    ST25R3916 *st25r = static_cast<ST25R3916 *>(_rfid);
    serialDevice->println("Place tag on reader...");
    if (!st25r->selectMifareClassic(5000, true)) {
        serialDevice->println("Read failed: tag not found");
        return false;
    }
    uint8_t recovered[6] = {0};
    const uint32_t startedMs = millis();
    auto progress = [](unsigned done, unsigned total, void *ctx) {
        static unsigned last = 0;
        if (done != last) {
            last = done;
            const uint32_t elapsed = millis() - *(const uint32_t *)ctx;
            const unsigned tried = (unsigned)((uint64_t)done * 65536u / 256u);
            serialDevice->println(
                "Trying keys: " + String(done) + "/" + String(total) + " tried=" + String(tried) +
                " ms=" + String(elapsed) + " rate=" +
                String(elapsed ? (unsigned)((uint64_t)tried * 1000u / elapsed) : 0u) + "/s"
            );
        }
        if (serialDevice->available() && serialDevice->read() == 'q') return false;
        return true;
    };
    const auto res = st25r->recoverKeyStaticNonce(
        (uint8_t)knownBlock,
        key,
        knownType.equalsIgnoreCase("B"),
        (uint8_t)targetBlock,
        targetType.equalsIgnoreCase("B"),
        recovered,
        progress,
        (void *)&startedMs
    );
    serialDevice->println(String("Static result: ") + ST25R3916::recoveryStatus(res));
    if (res == ST25R3916::RecoveryResult::Verified) {
        // Printed only so the operator can re-test it; the caller redacts logs.
        char buf[13];
        for (int i = 0; i < 6; i++) snprintf(buf + i * 2, 3, "%02X", recovered[i]);
        serialDevice->println(String("Recovered key: ") + buf);
    }
    return res == ST25R3916::RecoveryResult::Verified;
}

// rfid mfcdarkside <block=4> [A|B]
// Read-only darkside key recovery for a static/weak nonce card. Prints no key.
uint32_t rfidMfcDarksideCallback(cmd *c) {
    Command cmd(c);
    uint8_t block = cmd.countArgs() > 0 ? (uint8_t)cmd.getArgument(0).getValue().toInt() : 4;
    String keyType = cmd.countArgs() > 1 ? cmd.getArgument(1).getValue() : String("A");
    const bool useB = keyType.equalsIgnoreCase("B");

    if (!_ensureRfid()) return false;
    if (bruceConfigPins.rfidModule != ST25R3916_SPI_MODULE &&
        bruceConfigPins.rfidModule != ST25R3916_I2C_MODULE) {
        serialDevice->println("ERROR: recovery requires the ST25R3916 module");
        return false;
    }
    ST25R3916 *st25r = static_cast<ST25R3916 *>(_rfid);
    uint8_t key[6] = {0};
    auto res = st25r->recoverKeyDarkside(
        block,
        useB,
        key,
        [](unsigned done, unsigned total, void *) {
            static unsigned last = 0;
            if (done != last && (done & 0x0F) == 0) {
                last = done;
                serialDevice->println("Darkside: " + String(done) + "/" + String(total));
            }
            delay(1);
            return true;
        },
        nullptr
    );
    serialDevice->println(String("Darkside result: ") + ST25R3916::recoveryStatus(res));
    return res == ST25R3916::RecoveryResult::Verified ||
           res == ST25R3916::RecoveryResult::AlreadyKnown;
}

// rfid mfcdiag <keyhex> [knownBlock=0] [targetBlock=4] [rounds=4]
// Read-only nonce/parity/PRNG diagnostic. Prints no key material.
uint32_t rfidMfcDiagCallback(cmd *c) {
    Command cmd(c);
    if (cmd.countArgs() < 1) {
        serialDevice->println("Usage: rfid mfcdiag <12-hex-key> [knownBlock=0] [targetBlock=4] [rounds=4]");
        return false;
    }
    String keyHex = cmd.getArgument(0).getValue();
    keyHex.trim();
    if (keyHex.length() != 12) {
        serialDevice->println("ERROR: key must be 12 hex characters");
        return false;
    }
    uint8_t key[6] = {0};
    for (int i = 0; i < 6; i++) {
        char hi = keyHex.charAt(i * 2);
        char lo = keyHex.charAt(i * 2 + 1);
        auto nib = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            return -1;
        };
        int h = nib(hi), l = nib(lo);
        if (h < 0 || l < 0) {
            serialDevice->println("ERROR: key is not hex");
            return false;
        }
        key[i] = (uint8_t)((h << 4) | l);
    }
    uint8_t knownBlock = cmd.countArgs() > 1 ? (uint8_t)cmd.getArgument(1).getValue().toInt() : 0;
    uint8_t targetBlock = cmd.countArgs() > 2 ? (uint8_t)cmd.getArgument(2).getValue().toInt() : 4;
    int rounds = cmd.countArgs() > 3 ? cmd.getArgument(3).getValue().toInt() : 4;

    if (!_ensureRfid()) return false;
    if (bruceConfigPins.rfidModule != ST25R3916_SPI_MODULE &&
        bruceConfigPins.rfidModule != ST25R3916_I2C_MODULE) {
        serialDevice->println("ERROR: diagnostics require the ST25R3916 module");
        return false;
    }
    ST25R3916 *st25r = static_cast<ST25R3916 *>(_rfid);
    int good = st25r->mfcNonceDiagnostics(knownBlock, key, false, targetBlock, false, rounds);
    serialDevice->println("Diag captures: " + String(good));
    return good >= 0;
}
#endif

void createRfidCommands(SimpleCLI *cli) {
    Command cmd = cli->addCompositeCmd("rfid,nfc");

    Command readCmd = cmd.addCommand("read", rfidReadCallback);
    readCmd.addPosArg("timeout", "5000");

    Command writeCmd = cmd.addCommand("write", rfidWriteCallback);
    writeCmd.addPosArg("timeout", "5000");

    Command cloneCmd = cmd.addCommand("clone", rfidCloneCallback);
    cloneCmd.addPosArg("timeout", "5000");

    cmd.addBoundlessCommand("emulate", rfidEmulateCallback);
    cmd.addCommand("erase", rfidEraseCallback);
    cmd.addCommand("info", rfidInfoCallback);
    Command saveCmd = cmd.addCommand("save", rfidSaveCallback);
    saveCmd.addPosArg("filename", "rfid_dump");
    saveCmd.addPosArg("format", "bruce");
    Command loadFileCmd = cmd.addCommand("loadfile", rfidLoadFileCallback);
    loadFileCmd.addPosArg("filepath", "/BruceRFID/rfid_dump.rfid");
    cmd.addBoundlessCommand("ndef", rfidNdefCallback);
    cmd.addCommand("reset", rfidResetCallback);

    Command autotestCmd = cmd.addCommand("autotest,test", rfidAutotestCallback);
    autotestCmd.addPosArg("mode", "read-write");
    autotestCmd.addPosArg("timeout", "5000");

#if !defined(LITE_VERSION)
    Command recoverCmd = cmd.addCommand("recover", rfidRecoverCallback);
    recoverCmd.addPosArg("timeout", "5000");
    recoverCmd.addPosArg("sector", "-1");

    Command mfcKeyCmd = cmd.addCommand("mfckey", rfidMfcKeyCallback);
    mfcKeyCmd.addPosArg("block", "7");
    mfcKeyCmd.addPosArg("keyType", "A");
    mfcKeyCmd.addPosArg("key", "");

    Command mfcDarksideCmd = cmd.addCommand("mfcdarkside", rfidMfcDarksideCallback);
    mfcDarksideCmd.addPosArg("block", "4");
    mfcDarksideCmd.addPosArg("keyType", "A");

    Command mfcMeasureCmd = cmd.addCommand("mfcmeasure", rfidMfcMeasureCallback);
    mfcMeasureCmd.addPosArg("block", "0");
    mfcMeasureCmd.addPosArg("keyType", "A");
    mfcMeasureCmd.addPosArg("key", "");

    Command mfcStaticCmd = cmd.addCommand("mfcstatic", rfidMfcStaticCallback);
    mfcStaticCmd.addPosArg("knownBlock", "0");
    mfcStaticCmd.addPosArg("knownKeyType", "A");    mfcStaticCmd.addPosArg("knownKey", "A0A1A2A3A4A5");
    mfcStaticCmd.addPosArg("targetBlock", "7");
    mfcStaticCmd.addPosArg("targetKeyType", "A");

    Command mfcDiagCmd = cmd.addCommand("mfcdiag", rfidMfcDiagCallback);
    mfcDiagCmd.addPosArg("key", "");
    mfcDiagCmd.addPosArg("knownBlock", "0");
    mfcDiagCmd.addPosArg("targetBlock", "4");
    mfcDiagCmd.addPosArg("rounds", "4");
#endif
}
