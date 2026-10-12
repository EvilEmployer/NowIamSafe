#include <cstddef>

#include "nias/nias.hh"
#include "win32_internal.hh"

// setjmp-style safe-points. The context is captured by RtlCaptureContext in the
// CALLER's frame (via the nias_safepoint_set macro), so there is no wrapper
// whose return-address slot could be reused. On a fault whose policy is
// unwind_to_safepoint, the handler calls safepoint_restore(), which
// RtlRestoreContext's straight back to the capture site (setting RIP directly,
// no `ret`). The intervening frames are abandoned without running destructors,
// the documented trade-off of this recovery mode.

namespace nias::win32 {

namespace {

struct SafePointFrame {
    CONTEXT ctx;           // offset 0: the RtlCaptureContext / RtlRestoreContext target
    volatile long landed;  // 0 = armed, 1 = resumed via restore
    SafePointFrame* prev;
};

thread_local SafePointFrame* g_top = nullptr;

SafePointFrame* frame_of(nias_safepoint* sp) noexcept {
    return reinterpret_cast<SafePointFrame*>(sp->storage);
}

}  // namespace

static_assert(sizeof(SafePointFrame) <= sizeof(nias_safepoint),
              "nias_safepoint storage is too small for a CONTEXT");
static_assert(offsetof(SafePointFrame, ctx) == 0,
              "CONTEXT must sit at offset 0 for the capture macro");

bool safepoint_available() noexcept { return g_top != nullptr; }

void safepoint_restore() noexcept {
    SafePointFrame* f = g_top;
    g_top = f->prev;  // pop before the jump
    f->landed = 1;
    RtlRestoreContext(&f->ctx, nullptr);  // does not return
    __builtin_unreachable();
}

}  // namespace nias::win32

extern "C" void nias__safepoint_arm(nias_safepoint* sp) {
    auto* f = nias::win32::frame_of(sp);
    f->landed = 0;
    f->prev = nias::win32::g_top;
    nias::win32::g_top = f;  // register before the capture that follows in the macro
}

extern "C" int nias__safepoint_landed(nias_safepoint* sp) {
    return nias::win32::frame_of(sp)->landed ? 1 : 0;
}

extern "C" void nias_safepoint_clear(nias_safepoint* sp) {
    auto* f = nias::win32::frame_of(sp);
    if (nias::win32::g_top == f) {
        nias::win32::g_top = f->prev;
    }
}
