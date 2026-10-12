#include <doctest/doctest.h>

#include "nias/policy.hh"

using namespace nias;

// The classification and planning pipeline is constexpr and total, so the core
// of the decision table is pinned at compile time; the TEST_CASEs below cover
// the same ground at runtime for readable failure output.
namespace {
constexpr FaultEvent kAv = [] {
    FaultEvent e;
    e.cls = FaultClass::access_violation;
    e.native_code = 0xC0000005u;
    e.av_access = AvAccess::read;
    return e;
}();

static_assert(classify(0xC0000005u) == FaultClass::access_violation);
static_assert(classify(0xE06D7363u) == FaultClass::cpp_exception);
static_assert(classify(0x12345678u) == FaultClass::other);
static_assert(PolicyTable{}.get(FaultClass::stack_overflow).action == Action::fast_fail);
static_assert(plan(kAv, PolicyTable{}, RuntimeFacts{.has_pdata = true}).action ==
              Action::unwind_one);
static_assert(plan(kAv, PolicyTable{}, RuntimeFacts{.has_pdata = false}).leaf_pop);
}  // namespace

TEST_CASE("classify maps native codes") {
    CHECK(classify(0xC0000005u) == FaultClass::access_violation);
    CHECK(classify(0xC000001Du) == FaultClass::illegal_instruction);
    CHECK(classify(0xC0000096u) == FaultClass::illegal_instruction);
    CHECK(classify(0xC0000094u) == FaultClass::divide_by_zero);
    CHECK(classify(0xC000008Eu) == FaultClass::divide_by_zero);
    CHECK(classify(0xC0000095u) == FaultClass::int_overflow);
    CHECK(classify(0x80000002u) == FaultClass::misalignment);
    CHECK(classify(0xC00000FDu) == FaultClass::stack_overflow);
    CHECK(classify(0x80000003u) == FaultClass::breakpoint);
    CHECK(classify(0xE06D7363u) == FaultClass::cpp_exception);
    CHECK(classify(0x12345678u) == FaultClass::other);
}

TEST_CASE("default policy table matches DESIGN table") {
    PolicyTable pt;
    CHECK(pt.get(FaultClass::access_violation).action == Action::unwind_one);
    CHECK(pt.get(FaultClass::divide_by_zero).action == Action::unwind_one);
    CHECK(pt.get(FaultClass::stack_overflow).action == Action::fast_fail);
    CHECK(pt.get(FaultClass::cpp_exception).action == Action::pass_through);
    CHECK(pt.get(FaultClass::breakpoint).action == Action::pass_through);
}

static FaultEvent av_event() {
    FaultEvent e;
    e.cls = FaultClass::access_violation;
    e.native_code = 0xC0000005u;
    e.av_access = AvAccess::read;
    return e;
}

TEST_CASE("plan: AV with .pdata unwinds one frame + sentinel") {
    PolicyTable pt;
    RuntimeFacts rf;
    rf.has_pdata = true;
    const RecoveryPlan p = plan(av_event(), pt, rf);
    CHECK(p.action == Action::unwind_one);
    CHECK(p.write_sentinel);
    CHECK_FALSE(p.leaf_pop);
}

TEST_CASE("plan: AV in a leaf (no .pdata, no frame) pops return address") {
    PolicyTable pt;
    RuntimeFacts rf;
    rf.has_pdata = false;
    rf.prologue_alloc = 0;
    const RecoveryPlan p = plan(av_event(), pt, rf);
    CHECK(p.action == Action::unwind_one);
    CHECK(p.leaf_pop);
    CHECK(p.write_sentinel);
}

TEST_CASE("plan: AV without .pdata but with a frame falls back to a stub") {
    PolicyTable pt;
    RuntimeFacts rf;
    rf.has_pdata = false;
    rf.prologue_alloc = 40;
    const RecoveryPlan p = plan(av_event(), pt, rf);
    CHECK(p.action == Action::stub_redirect);
    CHECK(p.stub_frame_adjust == 40u);
    CHECK(p.write_sentinel);
}

TEST_CASE("plan: C++ throw is passed through untouched") {
    PolicyTable pt;
    FaultEvent e;
    e.cls = FaultClass::cpp_exception;
    e.native_code = 0xE06D7363u;
    const RecoveryPlan p = plan(e, pt, RuntimeFacts{});
    CHECK(p.action == Action::pass_through);
    CHECK_FALSE(p.write_sentinel);
}

TEST_CASE("plan: stack overflow fast-fails") {
    PolicyTable pt;
    FaultEvent e;
    e.cls = FaultClass::stack_overflow;
    e.native_code = 0xC00000FDu;
    const RecoveryPlan p = plan(e, pt, RuntimeFacts{});
    CHECK(p.action == Action::fast_fail);
}

TEST_CASE("plan: safe-point policy keeps or degrades on availability") {
    PolicyTable pt;
    pt.set(FaultClass::access_violation, Action::unwind_to_safepoint);

    RuntimeFacts has;
    has.safepoint_available = true;
    CHECK(plan(av_event(), pt, has).action == Action::unwind_to_safepoint);

    RuntimeFacts none;
    none.safepoint_available = false;
    none.has_pdata = true;
    const RecoveryPlan degraded = plan(av_event(), pt, none);
    CHECK(degraded.action == Action::unwind_one);
    CHECK(degraded.write_sentinel);
}
