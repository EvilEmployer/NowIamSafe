#include <atomic>
#include <utility>

#include "nias/decode.hh"
#include "nias/nias.hh"
#include "win32_internal.hh"

namespace nias {

namespace {

PVOID g_handler = nullptr;
PolicyTable g_policy;
std::uint16_t g_depth = 16;
std::atomic<bool> g_inited{false};

std::atomic<std::uint64_t> g_faults{0};
std::atomic<std::uint64_t> g_recovered{0};
std::atomic<std::uint64_t> g_passed{0};

// Re-entry guard: if our own handler faults, bail to the next handler instead
// of recursing forever.
thread_local int tls_in_handler = 0;

std::uint64_t now_qpc() noexcept {
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return static_cast<std::uint64_t>(li.QuadPart);
}

void build_record(FaultRecord& rec, const FaultEvent& ev, const RecoveryPlan& p,
                  const CONTEXT& ctx) noexcept {
    rec.magic = kRecordMagic;
    rec.version = kRecordVersion;
    rec.timestamp = now_qpc();
    rec.thread_id = ev.thread_id;
    rec.native_code = ev.native_code;
    rec.fault_class = std::to_underlying(ev.cls);
    rec.av_access = std::to_underlying(ev.av_access);
    rec.action_taken = std::to_underlying(p.action);

    const DecodeInfo d = decode_at(ev.code, ev.code_avail, ev.ctx.rip);
    rec.insn_length = d.valid ? d.length : 0;

    rec.fault_address = ev.fault_address;
    rec.rip = ev.ctx.rip;

    PVOID base = nullptr;
    RtlPcToFileHeader(reinterpret_cast<PVOID>(ev.ctx.rip), &base);
    rec.rip_module_base = reinterpret_cast<std::uint64_t>(base);
    rec.rip_rva = base ? ev.ctx.rip - reinterpret_cast<std::uint64_t>(base) : ev.ctx.rip;

    for (int i = 0; i < 16; ++i) {
        rec.gpr[i] = ev.ctx.gpr[i];
    }
    rec.eflags = ev.ctx.eflags;

    std::uint16_t depth = g_depth;
    if (depth > kMaxFrames) {
        depth = kMaxFrames;
    }
    rec.frame_count = win32::capture_backtrace(ctx, rec.frames, depth);
}

LONG CALLBACK handler(EXCEPTION_POINTERS* ep) {
    if (tls_in_handler) {
        return EXCEPTION_CONTINUE_SEARCH;  // faulted inside ourselves
    }
    tls_in_handler = 1;
    struct Guard {
        ~Guard() { tls_in_handler = 0; }
    } guard;

    const EXCEPTION_RECORD* er = ep->ExceptionRecord;
    CONTEXT* ctx = ep->ContextRecord;

    FaultEvent ev;
    win32::fill_event(ev, *er, *ctx);
    g_faults.fetch_add(1, std::memory_order_relaxed);

    const RuntimeFacts facts = win32::gather_facts(*ctx);
    const RecoveryPlan p = plan(ev, g_policy, facts);

    // Snapshot everything (backtrace included) from the original context before
    // apply() rewrites it.
    FaultRecord rec{};
    build_record(rec, ev, p, *ctx);
    win32::log_push(rec);

    switch (win32::apply(p, *ctx)) {
        case win32::Disposition::continue_execution:
            g_recovered.fetch_add(1, std::memory_order_relaxed);
            return EXCEPTION_CONTINUE_EXECUTION;
        case win32::Disposition::continue_search:
            g_passed.fetch_add(1, std::memory_order_relaxed);
            return EXCEPTION_CONTINUE_SEARCH;
        case win32::Disposition::jump_safepoint:
            g_recovered.fetch_add(1, std::memory_order_relaxed);
            tls_in_handler = 0;          // clear the guard before the non-returning jump
            win32::safepoint_restore();  // RtlRestoreContext; does not return
        case win32::Disposition::fast_fail:
        case win32::Disposition::terminate:
            TerminateProcess(GetCurrentProcess(),
                             0xDEAD0000u | (er->ExceptionCode & 0xFFFFu));
            return EXCEPTION_CONTINUE_SEARCH;  // unreachable
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

bool init(const Config& cfg) noexcept {
    bool expected = false;
    if (!g_inited.compare_exchange_strong(expected, true)) {
        return true;  // already installed
    }
    g_policy = cfg.policy;
    g_depth = cfg.backtrace_depth;

    if (!win32::log_start(cfg.log_path, cfg.ring_capacity_pow2)) {
        g_inited.store(false, std::memory_order_release);
        return false;
    }
    g_handler = AddVectoredExceptionHandler(cfg.first_handler ? 1u : 0u, handler);
    if (g_handler == nullptr) {
        win32::log_stop();
        g_inited.store(false, std::memory_order_release);
        return false;
    }
    return true;
}

void shutdown() noexcept {
    if (!g_inited.load(std::memory_order_acquire)) {
        return;
    }
    if (g_handler != nullptr) {
        RemoveVectoredExceptionHandler(g_handler);
        g_handler = nullptr;
    }
    win32::log_stop();
    g_inited.store(false, std::memory_order_release);
}

Stats stats() noexcept {
    return Stats{
        g_faults.load(std::memory_order_relaxed),
        g_recovered.load(std::memory_order_relaxed),
        g_passed.load(std::memory_order_relaxed),
        win32::log_dropped(),
    };
}

void set_policy(FaultClass cls, Action action) noexcept { g_policy.set(cls, action); }

}  // namespace nias

extern "C" int nias_init_default(void) {
    return nias::init(nias::Config{}) ? 1 : 0;
}

extern "C" void nias_shutdown(void) { nias::shutdown(); }
