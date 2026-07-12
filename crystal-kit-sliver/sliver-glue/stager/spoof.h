#ifndef SPOOF_H
#define SPOOF_H
#include <windows.h>

/* Populate signal-frame + gadget addresses. Returns 1 on success, 0 on
 * failure (in which case spoof_vp silently falls back to plain
 * VirtualProtect, preserving baseline behaviour). Call once before any
 * spoof_vp use. */
int  spoof_init(void);

/* Drop-in VirtualProtect replacement that synthesises an ntdll/kernel32
 * caller chain so a stack walk from inside kernelbase!VirtualProtect
 * resolves the topmost user-module frame to ntdll, not the caller DLL. */
BOOL spoof_vp(void *addr, SIZE_T size, DWORD newProt, DWORD *oldProt);

#endif
