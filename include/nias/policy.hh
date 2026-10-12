#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

#include "nias/fault.hh"

namespace nias {

// What to do with a trapped fault. The Win32 layer executes the chosen action
// against the real CONTEXT; the choice itself is computed here, portably.
enum class Action : std::uint8_t {
    pass_through,         // EXCEPTION_CONTINUE_SEARCH: log only, let normal handling run
    unwind_one,           // RtlVirtualUnwind one frame, write sentinel, continue
    unwind_to_safepoint,  // unwind to the nearest registered safe-point
    skip_instruction,     // advance RIP past the faulting instruction (opt-in, unsafe)
    stub_redirect,        // point RIP at a generated "balance + return 0" stub
    fast_fail,            // log then __fastfail
    terminate,            // log then ExitProcess
};

struct Policy {
    Action action = Action::pass_through;
};

// Per-class reaction table, constructed with the DESIGN.md §5 defaults. constexpr
// throughout so a caller can build and query a table at compile time (the tests
// do), and so the default table is a constant with no runtime initializer.
class PolicyTable {
public:
    constexpr PolicyTable() noexcept {
        set(FaultClass::access_violation, Action::unwind_one);
        set(FaultClass::illegal_instruction, Action::unwind_one);
        set(FaultClass::divide_by_zero, Action::unwind_one);
        set(FaultClass::int_overflow, Action::unwind_one);
        set(FaultClass::misalignment, Action::unwind_one);
        set(FaultClass::stack_overflow, Action::fast_fail);
        set(FaultClass::breakpoint, Action::pass_through);
        set(FaultClass::cpp_exception, Action::pass_through);
        set(FaultClass::other, Action::pass_through);
    }

    constexpr void set(FaultClass c, Action a) noexcept { table_[idx(c)].action = a; }
    [[nodiscard]] constexpr Policy get(FaultClass c) const noexcept { return table_[idx(c)]; }

private:
    static constexpr std::size_t idx(FaultClass c) noexcept {
        return std::to_underlying(c);
    }
    std::array<Policy, static_cast<std::size_t>(FaultClass::count_)> table_{};
};

// Runtime facts the Win32 layer discovers before planning recovery.
struct RuntimeFacts {
    bool has_pdata = false;           // RtlLookupFunctionEntry(rip) != nullptr
    bool safepoint_available = false;  // a safe-point is registered up-stack
    std::uint32_t prologue_alloc = 0;  // best-effort frame size (stub fallback only)
};

// The concrete recovery steps, derived from policy + facts. Still portable:
// no CONTEXT is touched here.
struct RecoveryPlan {
    Action action = Action::pass_through;
    bool write_sentinel = false;  // zero RAX/RDX/XMM0 on the recovered context
    bool leaf_pop = false;        // target has no frame: pop the return address
    std::uint32_t stub_frame_adjust = 0;
};

namespace detail {

// Resolve a hardware-fault recovery when the chosen action is a frame unwind.
// Picks the concrete mechanism from the runtime facts:
//   .pdata present        -> RtlVirtualUnwind one frame
//   no .pdata, no frame    -> leaf: pop the return address
//   no .pdata, has frame   -> stub fallback sized to the scanned prologue
constexpr void resolve_unwind(RecoveryPlan& p, const RuntimeFacts& rf) noexcept {
    p.write_sentinel = true;
    if (rf.has_pdata) {
        p.action = Action::unwind_one;
        p.leaf_pop = false;
    } else if (rf.prologue_alloc == 0) {
        p.action = Action::unwind_one;
        p.leaf_pop = true;
    } else {
        p.action = Action::stub_redirect;
        p.stub_frame_adjust = rf.prologue_alloc;
    }
}

}  // namespace detail

// Resolve the policy for an event into concrete steps. Pure and total, hence
// constexpr: the plan for a given (class, facts) is verified at compile time.
[[nodiscard]] constexpr RecoveryPlan plan(const FaultEvent& ev, const PolicyTable& pt,
                                          const RuntimeFacts& rf) noexcept {
    RecoveryPlan p;
    p.action = pt.get(ev.cls).action;

    switch (p.action) {
        case Action::unwind_one:
            detail::resolve_unwind(p, rf);
            break;
        case Action::unwind_to_safepoint:
            if (!rf.safepoint_available) {
                detail::resolve_unwind(p, rf);  // no safe-point up-stack: degrade
            }
            break;
        case Action::stub_redirect:
            p.write_sentinel = true;
            p.stub_frame_adjust = rf.prologue_alloc;
            break;
        case Action::skip_instruction:
        case Action::pass_through:
        case Action::fast_fail:
        case Action::terminate:
            break;
    }
    return p;
}

}  // namespace nias
