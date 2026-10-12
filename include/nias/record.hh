#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace nias {

inline constexpr std::uint32_t kRecordMagic = 0x5341494E;  // "NIAS"
inline constexpr std::uint16_t kRecordVersion = 1;
inline constexpr std::size_t kMaxFrames = 32;

// Fixed-layout, trivially-copyable fault record. The hot path fills one of
// these on the stack and hands it to the ring; symbolization happens offline
// against the PDB, so only {module_base, rva} pairs are stored, never symbols.
//
// Laid out at natural alignment (not packed): a packed struct would make every
// 64-bit field a misaligned access, which is UB and trips UBSan. Padding is
// explicit so the layout is deterministic and identical under MSVC and mingw;
// the static_asserts below lock the wire format.
struct FaultRecord {
    std::uint32_t magic;        // 0
    std::uint16_t version;      // 4
    std::uint16_t frame_count;  // 6
    std::uint64_t timestamp;    // 8   QPC ticks (or rdtsc on the Wine harness)
    std::uint32_t thread_id;    // 16
    std::uint32_t native_code;  // 20
    std::uint8_t fault_class;   // 24
    std::uint8_t av_access;     // 25
    std::uint8_t action_taken;  // 26
    std::uint8_t insn_length;   // 27
    std::uint32_t reserved0;    // 28  keeps fault_address 8-byte aligned
    std::uint64_t fault_address;      // 32
    std::uint64_t rip;                // 40
    std::uint64_t rip_module_base;    // 48
    std::uint64_t rip_rva;            // 56
    std::uint64_t gpr[16];            // 64
    std::uint32_t eflags;             // 192
    std::uint32_t reserved1;          // 196

    struct Frame {
        std::uint64_t module_base;
        std::uint64_t rva;
    } frames[kMaxFrames];  // 200
};

static_assert(std::is_trivially_copyable_v<FaultRecord>,
              "record is memcpy'd on the hot path");
static_assert(sizeof(FaultRecord::Frame) == 16, "frame layout is part of the wire format");
static_assert(sizeof(FaultRecord) == 200 + kMaxFrames * 16,
              "unexpected record layout: wire format changed");

// Compact wire size: fixed header + only the populated frames.
std::size_t record_size(const FaultRecord& r) noexcept;

// Serialize `r` into `out` (compact form). Returns bytes written, or 0 if the
// buffer is too small or the record is malformed.
std::size_t encode(const FaultRecord& r, std::uint8_t* out, std::size_t cap) noexcept;

// Parse a compact record. Returns false on bad magic/version/length.
bool decode(const std::uint8_t* in, std::size_t len, FaultRecord& out) noexcept;

}  // namespace nias
