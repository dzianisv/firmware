#ifndef _PINS_ARDUINO_H_
#define _PINS_ARDUINO_H_

// M5Stack Cardputer ADV pin mapping
// ESP32-S3 based, ST25R3916B NFC unit on I2C Port A

// I2C Port A (GROVE) — shared with TCA8418 keyboard (0x34) and ST25R3916B NFC (0x50)
#define SDA_PIN 2
#define SCL_PIN 1
#define SDA 2
#define SCL 1

// Arduino SPI pin aliases. Project build flags define the *_PIN macros.
#define SCK 40
#define MOSI 14
#define MISO 39
#define SS 1

// ST25R3916B I2C and SPI pin macros are supplied by the board environment flags.
#define ST25R_I2C_ADDRESS 0x50

// Display
#define TFT_MOSI 35
#define TFT_SCLK 36
#define TFT_CS 37
#define TFT_DC 34
#define TFT_RST 33
#define TFT_BL 38

// SD card, buttons, RGB LED, IR, keyboard and audio pins are supplied by
// the m5stack-cardputer-adv PlatformIO environment flags.

#endif
