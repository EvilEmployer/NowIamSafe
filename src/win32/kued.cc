#include <Zydis/Zydis.h>

#include <atomic>
#include <cstdint>
#include <cstring>

#include "nias/nias.hh"
#include "win32_internal.hh"

// Globals the asm thunk reads (rip-relative). Resolved at install time.
extern "C" {
std::uint32_t nias_kued_exc_off = 0;
std::uint32_t nias_kued_ctx_off = 0;
void* nias_kued_p_dispatch = nullptr;  // RtlDispatchException
void* nias_kued_p_continue = nullptr;  // NtContinue
void* nias_kued_p_raise = nullptr;     // NtRaiseException
void nias_kued_thunk();                // defined in kued_thunk.S
}

namespace nias::win32 {

namespace {

thread_local int tls_in_kued = 0;
std::atomic<std::uint64_t> g_kued_hits{0};

// Saved original bytes, for uninstall (keeps the hook's blast radius small).
std::uint8_t* g_hook_addr = nullptr;
std::uint8_t g_orig_bytes[32];
std::size_t g_orig_len = 0;

struct KuedLayout {
    bool ok = false;
    std::uint32_t exc_off = 0;   // ExceptionRecord = rsp + exc_off (passed in RCX)
    std::uint32_t ctx_off = 0;   // ContextRecord   = rsp + ctx_off (passed in RDX)
    std::size_t patch_len = 0;   // whole-instruction bytes covering the 14-byte jmp
    std::uint64_t dispatch = 0;  // RtlDispatchException, resolved from the prologue's call
};

// Learn how the real KiUserExceptionDispatcher derives the record pointers from
// RSP, so the thunk adapts to the build instead of hard-coding offsets. The
// register convention is fixed by RtlDispatchException(ExceptionRecord in RCX,
// ContextRecord in RDX).
//
// The pointers are not always a single `lea reg, [rsp+disp]`: Win11 (26100)
// splits it into `mov reg, rsp` + `add reg, imm`, with the same sequence
// appearing twice (once to feed the instrumentation callback, once for the real
// RtlDispatchException call). So track each of RCX/RDX as a running offset from
// RSP and read it off at the first relative CALL (RtlDispatchException); the
// indirect callback call does not end the walk.
KuedLayout analyze_kued(const std::uint8_t* code, std::size_t avail) noexcept {
    KuedLayout r;
    ZydisDecoder dec;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64,
                                       ZYDIS_STACK_WIDTH_64))) {
        return r;
    }

    // Per-register model: offset from entry RSP, valid only while tracks_rsp.
    struct RspRel {
        std::int64_t off = 0;
        bool tracks = false;
    } rcx, rdx;

    auto reg_slot = [&](ZydisRegister reg) -> RspRel* {
        if (reg == ZYDIS_REGISTER_RCX) return &rcx;
        if (reg == ZYDIS_REGISTER_RDX) return &rdx;
        return nullptr;
    };

    bool got_dispatch = false, got_offsets = false;
    std::size_t off = 0;
    while (off < avail) {
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, avail - off,
                                                 &insn, ops))) {
            break;
        }

        // First relative CALL is RtlDispatchException (the callback call is
        // indirect, through a register). Snapshot the record offsets there.
        if (insn.mnemonic == ZYDIS_MNEMONIC_CALL && !got_dispatch &&
            insn.operand_count_visible >= 1 &&
            ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            ops[0].imm.is_relative) {
            ZyanU64 abs = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                    &insn, &ops[0], reinterpret_cast<ZyanU64>(code + off),
                    &abs))) {
                r.dispatch = abs;
                got_dispatch = true;
                if (rcx.tracks && rdx.tracks) {
                    r.exc_off = static_cast<std::uint32_t>(rcx.off);
                    r.ctx_off = static_cast<std::uint32_t>(rdx.off);
                    got_offsets = true;
                }
            }
        }

        // Update the RSP-relative model for RCX/RDX.
        if (insn.operand_count_visible >= 2 &&
            ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            RspRel* dst = reg_slot(ops[0].reg.value);
            if (dst != nullptr) {
                const ZydisDecodedOperand& s = ops[1];
                if (insn.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    s.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    s.reg.value == ZYDIS_REGISTER_RSP) {
                    dst->off = 0;
                    dst->tracks = true;
                } else if (insn.mnemonic == ZYDIS_MNEMONIC_LEA &&
                           s.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                           s.mem.base == ZYDIS_REGISTER_RSP &&
                           s.mem.index == ZYDIS_REGISTER_NONE) {
                    dst->off = s.mem.disp.value;
                    dst->tracks = true;
                } else if (insn.mnemonic == ZYDIS_MNEMONIC_ADD && dst->tracks &&
                           s.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    dst->off += s.imm.value.s;
                } else {
                    dst->tracks = false;  // clobbered some other way
                }
            }
        }

        off += insn.length;
        if (r.patch_len < 14) {
            r.patch_len = off;
        }
        if (got_dispatch) {
            break;
        }
    }
    r.ok = got_offsets && got_dispatch && r.patch_len >= 14 &&
           r.patch_len <= 32;
    return r;
}

}  // namespace

std::uint64_t kued_hits() noexcept {
    return g_kued_hits.load(std::memory_order_relaxed);
}

bool install_kued() noexcept {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return false;
    }
    auto* kued = reinterpret_cast<std::uint8_t*>(
        GetProcAddress(ntdll, "KiUserExceptionDispatcher"));
    // RtlDispatchException is not exported by name; its address is recovered
    // from the prologue's own call (analyze_kued). NtContinue/NtRaiseException
    // are exported.
    nias_kued_p_continue =
        reinterpret_cast<void*>(GetProcAddress(ntdll, "NtContinue"));
    nias_kued_p_raise =
        reinterpret_cast<void*>(GetProcAddress(ntdll, "NtRaiseException"));
    if (kued == nullptr || nias_kued_p_continue == nullptr ||
        nias_kued_p_raise == nullptr) {
        return false;
    }

    const KuedLayout a = analyze_kued(kued, 48);
    if (!a.ok) {
        return false;
    }
    nias_kued_exc_off = a.exc_off;
    nias_kued_ctx_off = a.ctx_off;
    nias_kued_p_dispatch = reinterpret_cast<void*>(a.dispatch);

    // jmp qword ptr [rip+0]; <8-byte absolute target>, NOP-padded to patch_len.
    std::uint8_t patch[32];
    patch[0] = 0xFF;
    patch[1] = 0x25;
    patch[2] = patch[3] = patch[4] = patch[5] = 0x00;
    const std::uint64_t target = reinterpret_cast<std::uint64_t>(&nias_kued_thunk);
    std::memcpy(patch + 6, &target, sizeof(target));
    for (std::size_t i = 14; i < a.patch_len; ++i) {
        patch[i] = 0x90;
    }

    DWORD old = 0;
    if (!VirtualProtect(kued, a.patch_len, PAGE_EXECUTE_READWRITE, &old)) {
        return false;
    }
    std::memcpy(g_orig_bytes, kued, a.patch_len);  // save for uninstall
    g_hook_addr = kued;
    g_orig_len = a.patch_len;
    std::memcpy(kued, patch, a.patch_len);
    VirtualProtect(kued, a.patch_len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), kued, a.patch_len);
    return true;
}

bool uninstall_kued() noexcept {
    if (g_hook_addr == nullptr || g_orig_len == 0) {
        return false;
    }
    DWORD old = 0;
    if (!VirtualProtect(g_hook_addr, g_orig_len, PAGE_EXECUTE_READWRITE, &old)) {
        return false;
    }
    std::memcpy(g_hook_addr, g_orig_bytes, g_orig_len);
    VirtualProtect(g_hook_addr, g_orig_len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), g_hook_addr, g_orig_len);
    g_hook_addr = nullptr;
    g_orig_len = 0;
    return true;
}

}  // namespace nias::win32

// Called by the asm thunk. Returns 1 to resume (NtContinue on the context), 0 to
// let the normal dispatch run.
extern "C" int nias_kued_handler(EXCEPTION_RECORD* er, CONTEXT* ctx) {
    using namespace nias::win32;
    if (tls_in_kued) {
        return 0;  // re-entry: fall through to normal dispatch
    }
    tls_in_kued = 1;
    struct Guard {
        ~Guard() { tls_in_kued = 0; }
    } guard;

    g_kued_hits.fetch_add(1, std::memory_order_relaxed);

    switch (process_fault(*er, *ctx)) {
        case Disposition::continue_execution:
            return 1;
        case Disposition::continue_search:
            return 0;
        case Disposition::jump_safepoint:
            tls_in_kued = 0;
            safepoint_restore();  // does not return
            return 1;
        case Disposition::fast_fail:
        case Disposition::terminate:
            TerminateProcess(GetCurrentProcess(),
                             0xDEAD0000u | (er->ExceptionCode & 0xFFFFu));
            return 0;
    }
    return 0;
}

namespace nias {
bool install_kued() noexcept { return win32::install_kued(); }
bool uninstall_kued() noexcept { return win32::uninstall_kued(); }
std::uint64_t kued_hits() noexcept { return win32::kued_hits(); }
KuedInfo kued_info() noexcept {
    return KuedInfo{nias_kued_exc_off, nias_kued_ctx_off, nias_kued_p_dispatch};
}
}  // namespace nias
