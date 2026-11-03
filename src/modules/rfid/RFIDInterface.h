/**
 * @file RFIDInterface.h
 * @author Rennan Cockles (https://github.com/rennancockles)
 * @brief Interface for RFID modules
 * @version 0.1
 * @date 2024-08-19
 */

#ifndef __RFID_INTERFACE_H__
#define __RFID_INTERFACE_H__

#include <globals.h>
#include <vector>

class RFIDInterface {
public:
    typedef struct {
        byte size;
        byte uidByte[10];
        byte sak;
        byte atqaByte[2];
    } Uid;

    typedef struct {
        String uid;
        String bcc;
        String sak;
        String atqa;
        String picc_type;
    } PrintableUID;

    typedef struct {
        byte begin = 0x03;
        byte messageSize;
        byte header = 0xD1;
        byte tnf = 0x01;
        byte payloadSize;
        byte payloadType;
        byte payload[140];
        byte end = 0xFE;
    } NdefMessage;

    enum ReturnCode {
        SUCCESS = 0,
        FAILURE = 1,
        TAG_NOT_PRESENT = 2,
        TAG_NOT_MATCH = 3,
        TAG_AUTH_ERROR = 4,
        NOT_IMPLEMENTED = 5,
    };

    enum NDEF_Payload_Type { NDEF_TEXT = 0x54, NDEF_URI = 0x55 };

    // Public "universal" MIFARE Classic key list (Flipper/Proxmark dictionaries).
    // Every candidate costs a fresh anticollision, so a failed authentication
    // that drops the card must reselect and continue rather than abort the
    // whole read; that abort, not the list size, caused the sector-0-only
    // regression seen with this list.
    uint8_t keys[55][6] = {
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
        {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5},
        {0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD},
        {0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A},
        {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        {0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97},
        {0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F},
        {0xA0, 0x47, 0x8C, 0xC3, 0x90, 0x91},
        {0x53, 0x3C, 0xB6, 0xC7, 0x23, 0xF6},
        {0x8F, 0xD0, 0xA4, 0xF2, 0x56, 0xE9},
        {0xA6, 0x45, 0x98, 0xA7, 0x74, 0x78},
        {0x26, 0x94, 0x0B, 0x21, 0xFF, 0x5D},
        {0xFC, 0x00, 0x01, 0x87, 0x78, 0xF7},
        {0x00, 0x00, 0x0F, 0xFE, 0x24, 0x88},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
        {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB},
        {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54},
        {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
        {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB},
        {0x31, 0x41, 0x59, 0x26, 0x53, 0x58},
        {0x27, 0x18, 0x28, 0x18, 0x28, 0x45},
        {0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A},
        {0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5},
        {0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F},
        {0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F},
        {0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0},
        {0x13, 0x57, 0x9B, 0xDF, 0x24, 0x68},
        {0xBA, 0xDB, 0xAD, 0xBA, 0xDB, 0xAD},
        {0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE},
        {0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34},
        {0xCA, 0xFE, 0xBA, 0xBE, 0x56, 0x78},
        {0xAB, 0xAD, 0xAB, 0xAD, 0xAB, 0xAD},
        {0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE},
        {0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F},
        {0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A},
        {0x3B, 0x7E, 0x15, 0x16, 0x28, 0xAE},
        {0x2A, 0x2C, 0x13, 0xCC, 0x24, 0x2A},
        {0x5C, 0x8F, 0xF9, 0x99, 0x0D, 0xA2},
        {0x75, 0xCC, 0xB5, 0x9C, 0x9B, 0xED},
        {0xD0, 0x1A, 0xFE, 0xEB, 0x89, 0x0A},
        {0x4B, 0x79, 0x1B, 0xEA, 0x7B, 0x6C},
        {0xB5, 0x78, 0xF3, 0x8A, 0x5C, 0x61},
        {0x96, 0xA3, 0x01, 0xBC, 0xE2, 0x67},
        {0x00, 0x00, 0x01, 0x4B, 0x5C, 0x31},
        {0x48, 0x45, 0x58, 0x41, 0x43, 0x54},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x0A},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0xFF},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE},
        {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6},
        {0x1F, 0x47, 0xB5, 0xD9, 0x1F, 0x47},
        {0xE8, 0xF6, 0x0A, 0x98, 0x4B, 0xB8}
    };

    Uid uid;
    PrintableUID printableUID;
    NdefMessage ndefMessage;
    std::vector<uint8_t> rawNdefRecord;
    String strAllPages = "";
    // Optional forced emulation mode set by the CLI (e.g. "t4t", "felica").
    // Empty = auto-detect from the loaded tag. Honored by drivers that support it.
    String emuMode = "";
    int totalPages = 0;
    int dataPages = 0;
    bool pageReadSuccess = false;
    int pageReadStatus = FAILURE;

    virtual ~RFIDInterface() {} // Virtual destructor

    /////////////////////////////////////////////////////////////////////////////////////
    // Life Cycle
    /////////////////////////////////////////////////////////////////////////////////////
    virtual bool begin() = 0;

    /////////////////////////////////////////////////////////////////////////////////////
    // Operations
    /////////////////////////////////////////////////////////////////////////////////////
    virtual int read(int cardBaudRate = 0) = 0; // cardBaudRate = 0 means MIFARE, 1 means FeliCa
    virtual int clone() = 0;
    virtual int erase() = 0;
    virtual int write(int cardBaudRate = 0) = 0;
    virtual int write_ndef() = 0;
    virtual int emulate() { return NOT_IMPLEMENTED; }
    virtual int load() = 0;
    // Load + parse a dump file by path (shared by the GUI and the serial CLI so
    // their behavior never diverges). The base class provides a generic Bruce
    // .rfid parser; drivers may override it for richer handling (e.g. MIFARE
    // Classic blocks/keys, NTAG version/signature/counters in ST25R3916).
    virtual int loadFromFile(const String &filepath);
    virtual int save(const String &filename) = 0;
    virtual int saveFlipper(const String &filename) { return NOT_IMPLEMENTED; }

    // One-line warning shown before emulation starts if the driver can't
    // fully reproduce the loaded tag. Empty = nothing to warn about.
    virtual String emulationCaveat() const { return ""; }

    // Build `ndefMessage` from a type ("url"/"text") and value. Shared by the
    // serial `rfid ndef` and `rfid emulate t4t` paths so the encoding is
    // identical regardless of entry point.
    void buildNdefMessage(const String &type, const String &value);

    // Build `rawNdefRecord` as an NFC Forum Wi-Fi Simple Config MIME record
    // ("application/vnd.wfa.wsc") that phones recognize for the "connect to
    // this network" prompt
    void buildWifiNdef(const String &ssid, const String &password);

    String statusMessage(int status) const {
        switch (status) {
            case SUCCESS: return String(F("Success"));
            case FAILURE: return String(F("Failed reading data blocks"));
            case TAG_NOT_PRESENT: return String(F("Failed reading. Tag not found"));
            case TAG_NOT_MATCH: return String(F("Error! Tags don't match"));
            case TAG_AUTH_ERROR: return String(F("Failed authenticating"));
            case NOT_IMPLEMENTED: return String(F("Not implemented"));
            default: return String();
        }
    }
};

#endif
