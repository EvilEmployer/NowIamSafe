#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

namespace nias {

struct DecodeInfo {
    bool valid = false;
    std::uint8_t length = 0;
    bool reads_memory = false;
    bool writes_memory = false;
    bool is_branch = false;  // jcc / jmp / call / ret
    bool is_call = false;
    bool is_ret = false;
    std::int32_t mem_base_reg = -1;  // ZydisRegister id of the memory base, or -1
    char mnemonic[24] = {};
};

// Decode a single instruction at `code` (x86-64 long mode). `avail` bounds the
// read window; it may be larger than the instruction. `runtime_addr` is the
// instruction's virtual address, used only for relative-target reporting.
DecodeInfo decode_at(const std::uint8_t* code, std::size_t avail,
                     std::uint64_t runtime_addr) noexcept;

// Best-effort sum of stack bytes claimed by a function prologue (push r64 and
// `sub rsp, imm`), scanning from `fn_start`. Used only to size a fallback stub
// for code that has no .pdata. Returns 0 when nothing recognizable is found.
std::uint32_t scan_prologue_alloc(const std::uint8_t* fn_start,
                                  std::size_t avail) noexcept;

// Heuristic function-start finder: scan backward from `rip_off` for the int3
// (0xCC) padding that separates functions on Windows (MSVC/clang emit it), and
// return the offset of the first byte after the nearest padding run. Returns
// nullopt if no boundary is found within `max_lookback` bytes. Used only to
// anchor scan_prologue_alloc for code without unwind metadata.
std::optional<std::size_t> find_function_start(const std::uint8_t* buf,
                                               std::size_t size,
                                               std::size_t rip_off,
                                               std::size_t max_lookback) noexcept;

}  // namespace nias
