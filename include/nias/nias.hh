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

}  // namespace nias

extern "C" {
// Install with default configuration (no file sink). Returns non-zero on success.
int nias_init_default(void);
void nias_shutdown(void);
}
