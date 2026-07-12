/*
 * ghost.h — PE section mapping helper
 *
 * Maps a modified copy of C:\Windows\System32\combase.dll as a MEM_IMAGE
 * section with the caller's payload bytes patched into CoUninitialize's
 * file offset. Returns the mapped payload address on success (caller may
 * CreateThread there), NULL on failure. Failure paths clean up all
 * resources and return NULL so the caller can fall back to an alternate
 * loading strategy.
 */

#ifndef GHOST_H
#define GHOST_H

#include <windows.h>

void *ghost_map(const void *payload, SIZE_T payload_len);

#endif
