"""
patch_core.py — PlatformIO extra script (pre-build)

Patches Arduino-ESP32 core framework files that are incompatible with
GCC 14.x toolchains.

Issues fixed:
  1. #include (...) inside extern "C" blocks — GCC 14 rejects C++ templates
     with C linkage. ALL includes (quoted and angle-bracket) are moved
     before the extern "C" block so templates are declared with C++ linkage.
  2. Includes must be emitted BEFORE the extern "C" { opening line (not
     before the closing }), otherwise types like esp_err_t are used before
     they are declared.
  3. Esp.h: getCpuFrequencyMhz() renamed to getCpuFreqMHz()
  4. Arduino.h: conflicting makeWord(uint8_t, uint8_t) overload
  5. Wire.cpp: SDA/SCL default pin macros; missing I2C driver function
     declarations (removed in ESP-IDF v5.x); missing <cstdint> for uint32_t
     / uint8_t types used in our forward declarations.
"""

import os

Import("env")  # noqa: F821

FRAMEWORK_DIR = env.PioPlatform().get_package_dir("framework-arduinoespressif32")
CORE_DIR = os.path.join(FRAMEWORK_DIR, "cores", "esp32")
LIBS_DIR = os.path.join(FRAMEWORK_DIR, "libraries")

# Headers to skip from auto-patching (handled manually or not needed)
_SKIP_HEADERS = {"sdkconfig.h"}


def _read(path: str) -> str:
    with open(path) as f:
        return f.read()


def _write(path: str, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)


def _move_all_includes_outside_extern_c(content: str) -> str:
    """
    Move ALL #include directives (quoted and angle-bracket) that appear
    inside an extern "C" block to before the block. This ensures C++ standard
    library templates are declared with C++ linkage, avoiding GCC 14's
    "template with C linkage" hard error.

    Includes are emitted BEFORE the extern "C" { line so that types they
    define (e.g. esp_err_t) are available to declarations inside the block.
    """
    lines = content.split("\n")
    new_lines: list[str] = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Detect start of extern "C" block
        starts_block = 'extern "C" {' in stripped

        if starts_block:
            # Collect all content inside the block until closing brace
            block_lines = [line]
            i += 1
            brace_depth = line.count("{") - line.count("}")
            includes_inside: list[str] = []
            non_include_inside: list[str] = []

            while i < n and brace_depth > 0:
                inner_line = lines[i]
                inner_stripped = inner_line.strip()
                block_lines.append(inner_line)
                brace_depth += inner_line.count("{") - inner_line.count("}")

                if inner_stripped.startswith("#include"):
                    includes_inside.append(inner_line)
                else:
                    non_include_inside.append(inner_line)

                if brace_depth <= 0:
                    break
                i += 1

            # Emit includes BEFORE the extern "C" block
            new_lines.extend(includes_inside)
            # Emit the extern "C" { opening line
            new_lines.append(line)
            # Emit non-include content from inside the block
            new_lines.extend(non_include_inside)
            # Emit the closing brace (last line of block if it's just "}")
            if block_lines and block_lines[-1].strip() == "}":
                new_lines.append("}")
            else:
                # The closing brace is on a separate line after the block content
                new_lines.append("}")
            i += 1
            continue

        new_lines.append(line)
        i += 1

    return "\n".join(new_lines)


def _patch_all_hal_headers() -> None:
    """Scan ALL .h files in cores/esp32 for extern "C" blocks containing
    #include directives, and move those includes outside the block."""
    if not os.path.isdir(CORE_DIR):
        print(f"patch_core: CORE_DIR not found: {CORE_DIR}")
        return

    count = 0
    for fname in sorted(os.listdir(CORE_DIR)):
        if not fname.endswith(".h"):
            continue
        if fname in _SKIP_HEADERS:
            continue
        path = os.path.join(CORE_DIR, fname)
        content = _read(path)
        if 'extern "C" {' not in content:
            continue
        # Only patch if there's an #include inside extern "C"
        # Quick check: does any line between extern "C" { and } start with #include?
        in_block = False
        has_include_inside = False
        for line in content.split("\n"):
            stripped = line.strip()
            if 'extern "C" {' in stripped:
                in_block = True
                continue
            if in_block and stripped == "}":
                in_block = False
                continue
            if in_block and stripped.startswith("#include"):
                has_include_inside = True
                break

        if not has_include_inside:
            continue

        new_content = _move_all_includes_outside_extern_c(content)
        if new_content != content:
            _write(path, new_content)
            count += 1
            print(f"patch_core: {fname} — moved includes outside extern C")

    print(f"patch_core: patched {count} HAL header(s)")


def _patch_esp_h() -> None:
    path = os.path.join(CORE_DIR, "Esp.h")
    if not os.path.isfile(path):
        return
    content = _read(path)
    if "getCpuFrequencyMhz()" in content:
        content = content.replace("getCpuFrequencyMhz()", "getCpuFreqMHz()")
        _write(path, content)
        print("patch_core: Esp.h — getCpuFrequencyMhz -> getCpuFreqMHz")


def _patch_arduino_h() -> None:
    path = os.path.join(CORE_DIR, "Arduino.h")
    if not os.path.isfile(path):
        return
    content = _read(path)
    modified = False

    # Remove conflicting makeWord(uint8_t, uint8_t) overload
    if "uint16_t makeWord(uint8_t h, uint8_t l);" in content:
        content = content.replace("uint16_t makeWord(uint8_t h, uint8_t l);\n", "")
        modified = True

    # Add <cstdlib> include before random() declarations to avoid conflicts
    # with C library random() declarations when included inside extern "C"
    if "long random(long);" in content and "#include <cstdlib>" not in content:
        # Insert <cstdlib> near the top, after the include guard
        lines = content.split("\n")
        insert_at = 0
        for idx, line in enumerate(lines):
            if "#ifndef ARDUINO_H" in line or "#define ARDUINO_H" in line:
                insert_at = idx + 2
                break
        if insert_at > 0:
            lines.insert(insert_at, "#include <cstdlib>")
            content = "\n".join(lines)
            modified = True

    if modified:
        _write(path, content)
        print("patch_core: Arduino.h — removed makeWord overload + added cstdlib")


def _patch_wire_cpp() -> None:
    path = os.path.join(LIBS_DIR, "Wire", "src", "Wire.cpp")
    if not os.path.isfile(path):
        print(f"patch_core: Wire.cpp not found at {path}")
        return
    content = _read(path)
    modified = False

    # Add SDA/SCL fallback defines right after the includes block
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

    # Ensure driver/i2c.h is included
    if '#include <driver/i2c.h>' not in content and '#include "driver/i2c.h"' not in content:
        lines = content.split("\n")
        last_include = 0
        for idx, line in enumerate(lines):
            if line.strip().startswith("#include"):
                last_include = idx + 1
        lines.insert(last_include, '#include <driver/i2c.h>')
        content = "\n".join(lines)
        modified = True

    # Add forward declarations for ESP-IDF I2C driver functions removed in
    # ESP-IDF v5.x but still referenced by Arduino-ESP32 3.3.9's Wire.cpp.
    if "int i2cDeinit(" not in content:
        lines = content.split("\n")
        insert_at = 0
        for idx, line in enumerate(lines):
            if line.strip().startswith("#include"):
                insert_at = idx + 1
            elif insert_at > 0:
                break
        # Add <cstdint> so uint32_t / uint8_t are available for our decls
        if "#include <cstdint>" not in content:
            lines.insert(insert_at, "#include <cstdint>")
            insert_at += 1

        i2c_decls = [
            '',
            '// ESP-IDF v5.x removed these legacy I2C driver functions.',
            '// Declared here so Wire.cpp compiles; linker resolves if',
            '// the ESP-IDF library still provides them.',
            '// void* used for buffer params to allow implicit uint8_t*->void* conversion.',
            'extern "C" {',
            '    int i2cDeinit(int num);',
            '    int i2cGetClock(int num, uint32_t *frequency);',
            '    int i2cSetClock(int num, uint32_t frequency);',
            '    int i2cWrite(int num, uint8_t addr, void *data,',
            '                 uint32_t length, uint32_t timeout);',
            '    int i2cWriteReadNonStop(int num, uint8_t addr,',
    '                      void *data_wr, uint32_t wr_len,',
    '                      void *data_rd, uint32_t rd_len,',
    '                      uint32_t timeout,',
    '                      void *rd_length);',
            '    int i2cRead(int num, uint8_t addr, void *data,',
    '                uint32_t length, uint32_t timeout,',
    '                void *read_length);',
            '}',
            '',
        ]
        for j, decl in enumerate(i2c_decls):
            lines.insert(insert_at + j, decl)
        content = "\n".join(lines)
        modified = True

    if modified:
        _write(path, content)
        print("patch_core: Wire.cpp — added cstdint, SDA/SCL defines + driver/i2c.h + i2c decls")


def main() -> None:
    print("patch_core: applying GCC 14 compatibility patches...")
    _patch_all_hal_headers()
    _patch_esp_h()
    _patch_arduino_h()
    _patch_wire_cpp()
    print("patch_core: done")


main()
