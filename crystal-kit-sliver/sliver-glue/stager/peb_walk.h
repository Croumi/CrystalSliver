/*
 * peb_walk.h — DJB2 hash resolver for PEB InMemoryOrderModuleList walk
 * and export-table lookup. Ported from StdHandleRelay Stealth namespace.
 *
 * Callers pass precomputed hashes (hash_defs.h, gen_hashes.py) so no DLL
 * or API name strings appear in .rdata.
 */
#ifndef PEB_WALK_H
#define PEB_WALK_H

#include <windows.h>
#include <stdint.h>

/* djb2 with polynomial 131, seed 5381. NUL-terminated ASCII input. */
uint64_t pw_djb2(const char *s);

/* Walk PEB InMemoryOrderModuleList; return DllBase for the module whose
 * BaseDllName (lowercased) hashes to `hash`. NULL if not resident. */
HMODULE pw_get_module(uint64_t hash);

/* Walk `mod`'s export directory; return address of the export whose name
 * hashes to `hash`. Forwarders return NULL. */
FARPROC pw_get_proc(HMODULE mod, uint64_t hash);

#endif /* PEB_WALK_H */
