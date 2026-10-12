// Naked entry thunk for the KiUserExceptionDispatcher hook (x64).
//
// The kernel enters KiUserExceptionDispatcher with RSP pointing into a
// kernel-built frame: ContextRecord at RSP+nias_kued_ctx_off and
// ExceptionRecord at RSP+nias_kued_exc_off (both discovered from the real
// prologue at install time, so no offset is hard-coded). RSP is 16-aligned and
// the CONTEXT's P1Home..P6Home double as the home/shadow area, exactly as the
// original relies on.
//
// We call nias_kued_handler first (so we sit ahead of RtlDispatchException and
// therefore the whole VEH chain). If it recovered, resume via NtContinue on the
// (possibly edited) CONTEXT. Otherwise we replicate the normal dispatch —
// RtlDispatchException, then NtContinue on success or NtRaiseException for the
// second chance — rather than trampolining the fragile prologue.

    .intel_syntax noprefix
    .text
    .globl nias_kued_thunk
    .def nias_kued_thunk; .scl 2; .type 32; .endef
nias_kued_thunk:
    // rcx = ExceptionRecord, rdx = ContextRecord
    mov   eax, dword ptr [rip + nias_kued_exc_off]
    mov   r10d, dword ptr [rip + nias_kued_ctx_off]
    lea   rcx, [rsp + rax]
    lea   rdx, [rsp + r10]

    push  rbp
    mov   rbp, rsp
    sub   rsp, 32
    and   rsp, -16
    call  nias_kued_handler              // int (ExceptionRecord, ContextRecord)
    mov   rsp, rbp
    pop   rbp
    test  eax, eax
    jnz   .Lrecovered

    // Not handled by us: run the normal dispatch ourselves.
    mov   eax, dword ptr [rip + nias_kued_exc_off]
    mov   r10d, dword ptr [rip + nias_kued_ctx_off]
    lea   rcx, [rsp + rax]
    lea   rdx, [rsp + r10]
    push  rbp
    mov   rbp, rsp
    sub   rsp, 32
    and   rsp, -16
    call  [rip + nias_kued_p_dispatch]   // RtlDispatchException(ER, CR) -> BOOLEAN
    mov   rsp, rbp
    pop   rbp
    test  al, al
    jz    .Lunhandled

    // A frame/vectored handler took it: continue with the updated context.
    mov   r10d, dword ptr [rip + nias_kued_ctx_off]
    lea   rcx, [rsp + r10]
    xor   edx, edx
    sub   rsp, 32
    and   rsp, -16
    call  [rip + nias_kued_p_continue]   // NtContinue(CR, FALSE) -> no return
    int3

.Lunhandled:
    // Nobody handled it: raise it again as a second-chance exception.
    mov   eax, dword ptr [rip + nias_kued_exc_off]
    mov   r10d, dword ptr [rip + nias_kued_ctx_off]
    lea   rcx, [rsp + rax]
    lea   rdx, [rsp + r10]
    xor   r8d, r8d                        // FirstChance = FALSE
    sub   rsp, 32
    and   rsp, -16
    call  [rip + nias_kued_p_raise]       // NtRaiseException(ER, CR, FALSE)
    int3

.Lrecovered:
    // Our handler edited the CONTEXT for recovery: resume there.
    mov   r10d, dword ptr [rip + nias_kued_ctx_off]
    lea   rcx, [rsp + r10]
    xor   edx, edx
    sub   rsp, 32
    and   rsp, -16
    call  [rip + nias_kued_p_continue]    // NtContinue(CR, FALSE) -> no return
    int3
