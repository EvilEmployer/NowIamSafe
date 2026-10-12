#pragma once

#include <cstdint>

#include "nias/policy.hh"

// Public surface of the library. The C++ facade takes a Config; a small C ABI
// is provided for injection and C consumers.
namespace nias {

struct Config {
    const char* log_path = nullptr;      // binary record sink; null => ring only
    std::uint32_t ring_capacity_pow2 = 1024;  // must be a power of two
    std::uint16_t backtrace_depth = 16;  // frames to capture (<= kMaxFrames)
    bool first_handler = true;           // install at the head of the VEH list
    PolicyTable policy{};                // per-class reaction (DESIGN defaults)
};

// Installs the vectored exception handler. Idempotent: a second call with the
// handler already installed returns true without reinstalling.
bool init(const Config& cfg) noexcept;

// Removes the handler and flushes/stops the log drain.
void shutdown() noexcept;

struct Stats {
    std::uint64_t faults_seen;
    std::uint64_t recovered;       // CONTINUE_EXECUTION returned
    std::uint64_t passed_through;  // CONTINUE_SEARCH returned
    std::uint64_t dropped_records; // ring was full
};

Stats stats() noexcept;

// Change the reaction for one fault class at runtime (overrides the Config value).
void set_policy(FaultClass cls, Action action) noexcept;

// v2: inline-hook KiUserExceptionDispatcher so faults are seen before the VEH
// chain (above software that clears the VEH list or runs its own Kued hook).
// Call after init(). Returns false if the prologue could not be analyzed or the
// patch failed. Version/ABI sensitive — see docs/DESIGN.md.
bool install_kued() noexcept;

// Restore the original KiUserExceptionDispatcher bytes.
bool uninstall_kued() noexcept;

// Number of faults the Kued hook has processed (0 until install_kued succeeds).
std::uint64_t kued_hits() noexcept;

// What the prologue analysis extracted (for diagnostics across Windows builds).
struct KuedInfo {
    std::uint32_t exc_off;  // ExceptionRecord offset from RSP
    std::uint32_t ctx_off;  // ContextRecord offset from RSP
    const void* dispatch;   // resolved RtlDispatchException
};
KuedInfo kued_info() noexcept;

}  // namespace nias

// Opaque storage for a safe-point, allocated by the caller (typically on the
// stack). Large enough for a CONTEXT plus bookkeeping; 16-byte aligned because
// CONTEXT holds XMM state.
struct nias_safepoint {
    alignas(16) unsigned char storage[1536];
};

extern "C" {
// Install with default configuration (no file sink). Returns non-zero on success.
int nias_init_default(void);
void nias_shutdown(void);

// Internal helpers for the nias_safepoint_set macro; not meant to be called
// directly. arm registers the safe-point; landed reports whether a fault has
// since unwound to it.
void nias__safepoint_arm(nias_safepoint* sp);
int nias__safepoint_landed(nias_safepoint* sp);

// Unregister a safe-point on the normal (no-fault) path.
void nias_safepoint_clear(nias_safepoint* sp);
}

// setjmp-style safe-point. Evaluates to 0 when first armed, and to 1 when
// execution resumes here because a fault unwound to this safe-point (policy
// unwind_to_safepoint). It must be a macro: the context has to be captured in
// the caller's own frame — a wrapper function's return-address slot is reused
// by later calls, so resuming through it lands in the wrong place. <windows.h>
// must be in scope for RtlCaptureContext / PCONTEXT.
//
//   nias_safepoint sp;
//   if (nias_safepoint_set(&sp) == 0) {
//       risky();                 // may fault
//       nias_safepoint_clear(&sp);
//   } else {
//       // recovered from a fault inside risky()
//   }
#define nias_safepoint_set(sp)                   \
    (nias__safepoint_arm(sp),                    \
     RtlCaptureContext((PCONTEXT)(sp)->storage), \
     nias__safepoint_landed(sp))
