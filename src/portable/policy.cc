#include "nias/policy.hh"

namespace nias {

FaultClass classify(std::uint32_t code) noexcept {
    switch (code) {
        case 0xC0000005u:  // ACCESS_VIOLATION
            return FaultClass::access_violation;
        case 0xC000001Du:  // ILLEGAL_INSTRUCTION
        case 0xC0000096u:  // PRIVILEGED_INSTRUCTION
            return FaultClass::illegal_instruction;
        case 0xC0000094u:  // INTEGER_DIVIDE_BY_ZERO
        case 0xC000008Eu:  // FLOAT_DIVIDE_BY_ZERO
            return FaultClass::divide_by_zero;
        case 0xC0000095u:  // INTEGER_OVERFLOW
            return FaultClass::int_overflow;
        case 0x80000002u:  // DATATYPE_MISALIGNMENT
            return FaultClass::misalignment;
        case 0xC00000FDu:  // STACK_OVERFLOW
            return FaultClass::stack_overflow;
        case 0x80000003u:  // BREAKPOINT
            return FaultClass::breakpoint;
        case 0xE06D7363u:  // MSVC C++ throw
            return FaultClass::cpp_exception;
        default:
            return FaultClass::other;
    }
}

PolicyTable::PolicyTable() noexcept {
    using A = Action;
    set(FaultClass::access_violation, A::unwind_one);
    set(FaultClass::illegal_instruction, A::unwind_one);
    set(FaultClass::divide_by_zero, A::unwind_one);
    set(FaultClass::int_overflow, A::unwind_one);
    set(FaultClass::misalignment, A::unwind_one);
    set(FaultClass::stack_overflow, A::fast_fail);
    set(FaultClass::breakpoint, A::pass_through);
    set(FaultClass::cpp_exception, A::pass_through);
    set(FaultClass::other, A::pass_through);
}

namespace {

// Resolve a hardware-fault recovery when the chosen action is a frame unwind.
// Picks the concrete mechanism from the runtime facts:
//   .pdata present        -> RtlVirtualUnwind one frame
//   no .pdata, no frame    -> leaf: pop the return address
//   no .pdata, has frame   -> stub fallback sized to the scanned prologue
void resolve_unwind(RecoveryPlan& p, const RuntimeFacts& rf) noexcept {
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

}  // namespace

RecoveryPlan plan(const FaultEvent& ev, const PolicyTable& pt,
                  const RuntimeFacts& rf) noexcept {
    RecoveryPlan p;
    p.action = pt.get(ev.cls).action;

    switch (p.action) {
        case Action::unwind_one:
            resolve_unwind(p, rf);
            break;
        case Action::unwind_to_safepoint:
            if (!rf.safepoint_available) {
                resolve_unwind(p, rf);  // no safe-point up-stack: degrade
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
