#include "win32_internal.hh"

#include <cstring>

#include "nias/decode.hh"
#include "nias/stub.hh"

namespace nias::win32 {

namespace {

// Lazily-constructed stub pool. Only reached for faults in code without unwind
// metadata and with a known frame size; dormant on the common path.
StubPool& stub_pool() noexcept {
    static StubPool pool;
    return pool;
}

void write_sentinel(CONTEXT& ctx) noexcept {
    // Return type is unknown, so zero every register that can carry a result.
    ctx.Rax = 0;
    ctx.Rdx = 0;
    std::memset(&ctx.Xmm0, 0, sizeof(ctx.Xmm0));
    std::memset(&ctx.Xmm1, 0, sizeof(ctx.Xmm1));
}

// Pop the return address off the stack as if the current (frameless) function
// executed its `ret`.
void leaf_return(CONTEXT& ctx) noexcept {
    ctx.Rip = *reinterpret_cast<const DWORD64*>(ctx.Rsp);
    ctx.Rsp += sizeof(DWORD64);
}

// Roll the context back to the caller using the function's unwind data.
bool unwind_caller(CONTEXT& ctx) noexcept {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(ctx.Rip, &image_base, nullptr);
    if (rf == nullptr) {
        return false;
    }
    CONTEXT unwound = ctx;
    PVOID handler_data = nullptr;
    DWORD64 establisher = 0;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, ctx.Rip, rf, &unwound,
                     &handler_data, &establisher, nullptr);
    ctx = unwound;
    return true;
}

}  // namespace

void fill_event(FaultEvent& ev, const EXCEPTION_RECORD& er,
                const CONTEXT& ctx) noexcept {
    ev.native_code = er.ExceptionCode;
    ev.cls = classify(er.ExceptionCode);
    ev.thread_id = GetCurrentThreadId();

    if (er.ExceptionCode == 0xC0000005u && er.NumberParameters >= 2) {
        switch (er.ExceptionInformation[0]) {
            case 0: ev.av_access = AvAccess::read; break;
            case 1: ev.av_access = AvAccess::write; break;
            case 8: ev.av_access = AvAccess::execute; break;
            default: ev.av_access = AvAccess::na; break;
        }
        ev.fault_address = er.ExceptionInformation[1];
    }

    ev.ctx.rip = ctx.Rip;
    ev.ctx.rsp = ctx.Rsp;
    ev.ctx.rbp = ctx.Rbp;
    ev.ctx.eflags = ctx.EFlags;
    ev.ctx.gpr[rax] = ctx.Rax;
    ev.ctx.gpr[rcx] = ctx.Rcx;
    ev.ctx.gpr[rdx] = ctx.Rdx;
    ev.ctx.gpr[rbx] = ctx.Rbx;
    ev.ctx.gpr[rsp_] = ctx.Rsp;
    ev.ctx.gpr[rbp_] = ctx.Rbp;
    ev.ctx.gpr[rsi] = ctx.Rsi;
    ev.ctx.gpr[rdi] = ctx.Rdi;
    ev.ctx.gpr[r8] = ctx.R8;
    ev.ctx.gpr[r9] = ctx.R9;
    ev.ctx.gpr[r10] = ctx.R10;
    ev.ctx.gpr[r11] = ctx.R11;
    ev.ctx.gpr[r12] = ctx.R12;
    ev.ctx.gpr[r13] = ctx.R13;
    ev.ctx.gpr[r14] = ctx.R14;
    ev.ctx.gpr[r15] = ctx.R15;

    // Bounded, page-safe window over the faulting instruction.
    const std::uint64_t rip = ctx.Rip;
    const std::uint64_t page_end = (rip | 0xFFFull) + 1;
    std::size_t avail = static_cast<std::size_t>(page_end - rip);
    if (avail > 15) {
        avail = 15;
    }
    ev.code = reinterpret_cast<const std::uint8_t*>(rip);
    ev.code_avail = avail;
}

RuntimeFacts gather_facts(const CONTEXT& ctx) noexcept {
    RuntimeFacts f;
    DWORD64 image_base = 0;
    f.has_pdata = RtlLookupFunctionEntry(ctx.Rip, &image_base, nullptr) != nullptr;
    f.safepoint_available = safepoint_available();
    f.prologue_alloc = 0;

    // No unwind data: try to size the frame for the stub fallback. Read only
    // within RIP's own page (it is mapped and executable, so reading back and
    // forth inside it cannot fault); a function start in an earlier page is
    // simply not found and we fall back to a leaf pop.
    if (!f.has_pdata) {
        constexpr std::uint64_t kPageMask = 0xFFFull;
        constexpr std::size_t kLookback = 256;
        const std::uint64_t page = ctx.Rip & ~kPageMask;
        const std::size_t rip_off = static_cast<std::size_t>(ctx.Rip - page);
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(page);
        if (const auto start =
                find_function_start(bytes, rip_off + 1, rip_off, kLookback)) {
            const std::size_t avail = (rip_off + 1) - *start;
            f.prologue_alloc = scan_prologue_alloc(bytes + *start, avail);
        }
    }
    return f;
}

Disposition apply(const RecoveryPlan& p, CONTEXT& ctx) noexcept {
    switch (p.action) {
        case Action::pass_through:
            return Disposition::continue_search;
        case Action::fast_fail:
            return Disposition::fast_fail;
        case Action::terminate:
            return Disposition::terminate;

        case Action::skip_instruction: {
            const DecodeInfo d = decode_at(
                reinterpret_cast<const std::uint8_t*>(ctx.Rip), 15, ctx.Rip);
            if (!d.valid) {
                return Disposition::fast_fail;
            }
            ctx.Rip += d.length;
            if (p.write_sentinel) {
                write_sentinel(ctx);
            }
            return Disposition::continue_execution;
        }

        case Action::stub_redirect: {
            void* stub = stub_pool().make_return_stub(p.stub_frame_adjust);
            if (stub == nullptr) {
                return Disposition::fast_fail;
            }
            ctx.Rip = reinterpret_cast<DWORD64>(stub);
            if (p.write_sentinel) {
                write_sentinel(ctx);
            }
            return Disposition::continue_execution;
        }

        case Action::unwind_one: {
            if (p.leaf_pop || !unwind_caller(ctx)) {
                leaf_return(ctx);
            }
            if (p.write_sentinel) {
                write_sentinel(ctx);
            }
            return Disposition::continue_execution;
        }

        case Action::unwind_to_safepoint:
            // Reached only when a safe-point is registered (plan() degrades to
            // unwind_one otherwise). The handler performs the non-returning
            // jump after clearing its re-entry guard.
            return Disposition::jump_safepoint;
    }
    return Disposition::continue_search;
}

std::uint16_t capture_backtrace(const CONTEXT& start, FaultRecord::Frame* out,
                                std::uint16_t max) noexcept {
    CONTEXT ctx = start;
    std::uint16_t n = 0;
    while (n < max && ctx.Rip != 0) {
        PVOID base = nullptr;
        RtlPcToFileHeader(reinterpret_cast<PVOID>(ctx.Rip), &base);
        out[n].module_base = reinterpret_cast<std::uint64_t>(base);
        out[n].rva = base ? ctx.Rip - reinterpret_cast<std::uint64_t>(base) : ctx.Rip;
        ++n;

        DWORD64 image_base = 0;
        PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(ctx.Rip, &image_base, nullptr);
        if (rf == nullptr) {
            break;  // leaf or no unwind data: stop rather than walk garbage
        }
        const DWORD64 prev_rip = ctx.Rip;
        PVOID handler_data = nullptr;
        DWORD64 establisher = 0;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, ctx.Rip, rf, &ctx,
                         &handler_data, &establisher, nullptr);
        if (ctx.Rip == prev_rip) {
            break;
        }
    }
    return n;
}

}  // namespace nias::win32
