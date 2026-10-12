#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

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

// Per-class reaction table. Constructed with the DESIGN.md §5 defaults.
class PolicyTable {
public:
    PolicyTable() noexcept;

    void set(FaultClass c, Action a) noexcept { table_[idx(c)].action = a; }
    Policy get(FaultClass c) const noexcept { return table_[idx(c)]; }

private:
    static constexpr std::size_t idx(FaultClass c) noexcept {
        return static_cast<std::size_t>(c);
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

// Resolve the policy for an event into concrete steps. Pure and total.
RecoveryPlan plan(const FaultEvent& ev, const PolicyTable& pt,
                  const RuntimeFacts& rf) noexcept;

}  // namespace nias
