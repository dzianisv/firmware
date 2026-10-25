"""
patch_core.py — PlatformIO extra script (pre-build)

Patches Arduino-ESP32 core framework files that are incompatible with
GCC 14.x toolchains.

Issues fixed:
  1. #include <...> (C++ standard library) inside extern "C" blocks — GCC 14
     rejects templates with C linkage. Move ONLY angle-bracket includes
     outside the block; keep quoted ESP-IDF headers inside so their types
     remain visible.
  2. Esp.h: getCpuFrequencyMhz() renamed to getCpuFreqMHz()
  3. Arduino.h: conflicting makeWord(uint8_t, uint8_t) overload
  4. Wire.cpp: SDA/SCL default pin macros not defined; missing I2C driver
     function declarations (removed in ESP-IDF v5.x)
"""

import os
from typing import Any

Import("env")  # noqa: F821

FRAMEWORK_DIR = env.PioPlatform().get_package_dir("framework-arduinoespressif32")
CORE_DIR = os.path.join(FRAMEWORK_DIR, "cores", "esp32")

PATCH_FLAG = os.path.join(FRAMEWORK_DIR, ".core_patched")


def _read(path: str) -> str:
    with open(path) as f:
        return f.read()


def _write(path: str, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)


def _move_cpp_includes_outside_extern_c(content: str) -> str:
    """
    Move #include <...> (C++ standard library) directives that appear inside
    an extern "C" block to before the block. Quoted #include "..." headers
    (ESP-IDF drivers, soc, etc.) are left inside so their C types remain
    visible to functions declared inside extern "C".
    """
    lines = content.split("\n")
    new_lines: list[str] = []
    i = 0
    in_extern_c = False
    cpp_includes_inside: list[str] = []

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if 'extern "C" {' in line and not in_extern_c:
            in_extern_c = True
            new_lines.append(line)
            i += 1
            continue

        if in_extern_c and stripped == "}":
            for inc in cpp_includes_inside:
                new_lines.append(inc)
            cpp_includes_inside = []
            in_extern_c = False
            new_lines.append(line)
            i += 1
            continue

        if in_extern_c and stripped.startswith('#include <'):
            cpp_includes_inside.append(line)
            i += 1
            continue

        new_lines.append(line)
        i += 1

    return "\n".join(new_lines)


# Core headers known to have extern "C" + C++ include conflicts
_HAL_HEADERS = [
    "esp32-hal-adc.h",
    "esp32-hal-cpu.h",
    "esp32-hal-dac.h",
    "esp32-hal-gpio.h",
    "esp32-hal-i2c.h",
    "esp32-hal-i2c-slave.h",
    "esp32-hal-ledc.h",
    "esp32-hal-ldo.h",
    "esp32-hal-log.h",
    "esp32-hal-matrix.h",
    "esp32-hal-periman.h",
    "esp32-hal-psram.h",
    "esp32-hal-rgb-led.h",
    "esp32-hal-spi.h",
    "esp32-hal-touch.h",
    "esp32-hal-touch-ng.h",
    "esp32-hal-timer.h",
    "esp32-hal-tinyusb.h",
    "esp32-hal-uart.h",
    "esp32-hal.h",
]


def _patch_all_hal_headers() -> None:
    for fname in _HAL_HEADERS:
        path = os.path.join(CORE_DIR, fname)
        if not os.path.isfile(path):
            continue
        content = _read(path)
        new_content = _move_cpp_includes_outside_extern_c(content)
        if new_content != content:
            _write(path, new_content)
            print(f"patch_core: {fname} — moved C++ includes outside extern C")


def _patch_esp_h() -> None:
    path = os.path.join(CORE_DIR, "Esp.h")
    content = _read(path)
    if "getCpuFrequencyMhz()" in content:
        content = content.replace("return getCpuFrequencyMhz();",
                                  "return getCpuFreqMHz();")
        _write(path, content)
        print("patch_core: Esp.h — getCpuFrequencyMhz -> getCpuFreqMHz")


def _patch_arduino_h() -> None:
    path = os.path.join(CORE_DIR, "Arduino.h")
    content = _read(path)
    if "uint16_t makeWord(uint8_t h, uint8_t l);" in content:
        content = content.replace(
            "uint16_t makeWord(uint8_t h, uint8_t l);\n", "")
        _write(path, content)
        print("patch_core: Arduino.h — removed conflicting makeWord overload")


def _patch_wire_cpp() -> None:
    LIBS_DIR = os.path.join(FRAMEWORK_DIR, "libraries")
    path = os.path.join(LIBS_DIR, "Wire", "src", "Wire.cpp")
    content = _read(path)
    modified = False

    # Add SDA/SCL fallback defines
    if "#ifndef SDA" not in content:
        lines = content.split("\n")
        insert_at = 0
        for idx, line in enumerate(lines):
            if "#include" in line:
                insert_at = idx + 1
            else:
                break
        lines.insert(insert_at, "#ifndef SDA")
        lines.insert(insert_at + 1, "#define SDA 21")
        lines.insert(insert_at + 2, "#endif")
        lines.insert(insert_at + 3, "#ifndef SCL")
        lines.insert(insert_at + 4, "#define SCL 22")
        lines.insert(insert_at + 5, "#endif")
        content = "\n".join(lines)
        modified = True

    # Ensure driver/i2c.h is included for I2C driver function declarations
    if '#include <driver/i2c.h>' not in content and '#include "driver/i2c.h"' not in content:
        lines = content.split("\n")
        last_include = 0
        for idx, line in enumerate(lines):
            if line.strip().startswith("#include"):
                last_include = idx + 1
        lines.insert(last_include, '#include <driver/i2c.h>')
        content = "\n".join(lines)
        modified = True

    # Add forward declarations for ESP-IDF I2C driver functions that were
    # removed in ESP-IDF v5.x but still referenced by Arduino-ESP32 3.3.9's
    # Wire.cpp. Declaring them here lets the compiler accept the calls;
    # if the ESP-IDF library still provides them (as deprecated wrappers),
    # the linker will resolve them.
    if "i2cDeinit" not in content:
        lines = content.split("\n")
        insert_at = 0
        for idx, line in enumerate(lines):
            if line.strip().startswith("#include"):
                insert_at = idx + 1
            elif insert_at > 0:
                break
        i2c_decls = [
            '',
            '// ESP-IDF v5.x removed these legacy I2C driver functions.',
            '// Declared here so Wire.cpp compiles; linker resolves if',
            '// the ESP-IDF library still provides them.',
            'extern "C" {',
            '    int i2cDeinit(int num);',
            '    int i2cGetClock(int num, uint32_t *frequency);',
            '    int i2cSetClock(int num, uint32_t frequency);',
            '    int i2cWrite(int num, uint8_t addr, uint8_t *data,',
            '                 uint32_t length, uint32_t timeout);',
            '    int i2cWriteReadNonStop(int num, uint8_t addr,',
            '                      uint8_t *data_wr, uint32_t wr_len,',
            '                      uint8_t *data_rd, uint32_t rd_len,',
            '                      uint32_t timeout,',
            '                      uint32_t *rd_length);',
            '    int i2cRead(int num, uint8_t addr, uint8_t *data,',
            '                uint32_t length, uint32_t timeout,',
            '                uint32_t *read_length);',
            '}',
            '',
        ]
        for j, decl in enumerate(i2c_decls):
            lines.insert(insert_at + j, decl)
        content = "\n".join(lines)
        modified = True

    if modified:
        _write(path, content)
        print("patch_core: Wire.cpp — added SDA/SCL defines + driver/i2c.h + i2c decls")


def main() -> None:
    if os.path.isfile(PATCH_FLAG):
        print("patch_core: already applied, skipping")
        return

    print("patch_core: applying GCC 14 compatibility patches...")
    _patch_all_hal_headers()
    _patch_esp_h()
    _patch_arduino_h()
    _patch_wire_cpp()

    # Touch the flag file so we don't re-patch on subsequent builds
    with open(PATCH_FLAG, "w") as f:
        f.write("")
    print("patch_core: done")


main()
