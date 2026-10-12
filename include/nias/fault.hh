#pragma once

#include <cstddef>
#include <cstdint>

namespace nias {

// Portable classification of a trapped exception. Independent of Windows headers
// so the decision logic builds and is tested natively off-target.
enum class FaultClass : std::uint8_t {
    access_violation,
    illegal_instruction,
    divide_by_zero,
    int_overflow,
    misalignment,
    stack_overflow,
    breakpoint,
    cpp_exception,
    other,
    count_,
};

enum class AvAccess : std::uint8_t {
    read = 0,
    write = 1,
    execute = 8,
    na = 0xFF,
};

// General-purpose register indices in x86-64 ModRM encoding order. The Win32
// adapter fills GpContext::gpr using these so portable code never needs the
// Windows CONTEXT layout.
enum GpReg : std::uint8_t {
    rax = 0, rcx, rdx, rbx, rsp_, rbp_, rsi, rdi,
    r8, r9, r10, r11, r12, r13, r14, r15,
    gpr_count,
};

struct GpContext {
    std::uint64_t rip = 0;
    std::uint64_t rsp = 0;
    std::uint64_t rbp = 0;
    std::uint64_t gpr[gpr_count] = {};
    std::uint32_t eflags = 0;
};

struct FaultEvent {
    FaultClass cls = FaultClass::other;
    AvAccess av_access = AvAccess::na;
    std::uint32_t native_code = 0;
    std::uint64_t fault_address = 0;  // AV target address; 0 otherwise
    std::uint32_t thread_id = 0;
    GpContext ctx{};

    // Readable window over the faulting instruction bytes, if available. The
    // decoder treats `code_avail` as a max bound, not the exact length.
    const std::uint8_t* code = nullptr;
    std::size_t code_avail = 0;
};

// Maps a native Windows exception code (e.g. 0xC0000005) to a FaultClass.
// Pure and total, so it is constexpr: the classification tables in the tests
// are checked at compile time, and the hot path pays nothing for it.
[[nodiscard]] constexpr FaultClass classify(std::uint32_t native_code) noexcept {
    switch (native_code) {
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

}  // namespace nias
