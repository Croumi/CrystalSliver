/*
 * peb_walk.c — minimal PEB + export-table resolver (djb2 h*131+c, seed 5381).
 *
 * Ported from StdHandleRelay Stealth::GetModuleByHash / GetProcAddressH but
 * stripped of forwarder-follow, batch resolve, and salt (LAZY MODE — the
 * launcher only needs single-hash lookups; forwarders on webio!WebSocket*
 * and combase!CoUninitialize don't apply).
 */

#include "peb_walk.h"

/* Minimal PEB / LDR shapes — winternl.h has these but coupling to it drags
 * conflicting UNICODE_STRING typedefs on some mingw variants. */
typedef struct _PW_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} PW_UNICODE_STRING;

typedef struct _PW_LDR_ENTRY {
    LIST_ENTRY        InLoadOrderLinks;
    LIST_ENTRY        InMemoryOrderLinks;
    LIST_ENTRY        InInitializationOrderLinks;
    PVOID             DllBase;
    PVOID             EntryPoint;
    ULONG             SizeOfImage;
    PW_UNICODE_STRING FullDllName;
    PW_UNICODE_STRING BaseDllName;
} PW_LDR_ENTRY;

typedef struct _PW_PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PW_PEB_LDR_DATA;

typedef struct _PW_PEB {
    BYTE              Reserved1[2];
    BYTE              BeingDebugged;
    BYTE              Reserved2[1];
    PVOID             Reserved3[2];
    PW_PEB_LDR_DATA  *Ldr;
} PW_PEB;

uint64_t pw_djb2(const char *s)
{
    uint64_t h = 5381ULL;
    unsigned char c;
    while ((c = (unsigned char)*s++))
        h = h * 131ULL + c;
    return h;
}

/* Hash a wide BaseDllName as lowercased ASCII (matches gen_hashes.py). */
static uint64_t pw_djb2_wlower(const WCHAR *ws, USHORT bytes)
{
    uint64_t h = 5381ULL;
    USHORT n = bytes / (USHORT)sizeof(WCHAR);
    for (USHORT i = 0; i < n; i++) {
        unsigned char c = (unsigned char)ws[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        h = h * 131ULL + c;
    }
    return h;
}

HMODULE pw_get_module(uint64_t hash)
{
    PW_PEB *peb = (PW_PEB *)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return NULL;

    LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY *cur = head->Flink; cur && cur != head; cur = cur->Flink) {
        PW_LDR_ENTRY *e = CONTAINING_RECORD(cur, PW_LDR_ENTRY, InMemoryOrderLinks);
        if (!e->BaseDllName.Buffer || !e->BaseDllName.Length) continue;
        if (pw_djb2_wlower(e->BaseDllName.Buffer, e->BaseDllName.Length) == hash)
            return (HMODULE)e->DllBase;
    }
    return NULL;
}

FARPROC pw_get_proc(HMODULE mod, uint64_t hash)
{
    if (!mod) return NULL;
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!rva) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + rva);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (pw_djb2(name) == hash) {
            DWORD f = funcs[ords[i]];
            /* Forwarder RVA falls inside the export directory — skip for
             * this loader; the target APIs (WebSocketBeginClientHandshake,
             * CoUninitialize, RtlAddFunctionTable) aren't forwarders. */
            if (f >= rva && f < rva + size) return NULL;
            return (FARPROC)(base + f);
        }
    }
    return NULL;
}
