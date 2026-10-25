#ifndef _PINS_ARDUINO_H_
#define _PINS_ARDUINO_H_

#include <Arduino.h>

// M5Stack Cardputer ADV pin mapping
// ESP32-S3 based, ST25R3916B NFC unit on I2C Port A

// I2C Port A (GROVE) — shared with TCA8418 keyboard (0x34) and ST25R3916B NFC (0x50)
#define SDA_PIN 2
#define SCL_PIN 1

// ST25R3916B NFC Unit — I2C on Port A
#define ST25R_I2C_SDA_PIN 2
#define ST25R_I2C_SCL_PIN 1
#define ST25R_I2C_ADDRESS 0x50

// SPI pins (shared with SD card, CC1101, NRF24, etc.)
#define SPI_SCK_PIN 40
#define SPI_MOSI_PIN 14
#define SPI_MISO_PIN 39
#define SPI_SS_PIN 1

// Display
#define TFT_MOSI 35
#define TFT_SCLK 36
#define TFT_CS 37
#define TFT_DC 34
#define TFT_RST 33
#define TFT_BL 38

// SD Card
#define SDCARD_CS 12
#define SDCARD_SCK 40
#define SDCARD_MISO 39
#define SDCARD_MOSI 14

// Buttons
#define BTN_PIN 0

// RGB LED
#define RGB_LED 21

// IR
#define TXLED 44

// Keyboard (TCA8418 on internal I2C)
#define TCA8418_SDA_PIN 8
#define TCA8418_SCL_PIN 9
#define TCA8418_INT_PIN 11

// Audio
#define ES8311_ADDR 0x18
#define PIN_CLK 43
#define I2S_DATA_PIN 46

#endif
