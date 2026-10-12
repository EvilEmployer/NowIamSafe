#pragma once

#include <windows.h>

#include <cstdint>

#include "nias/fault.hh"
#include "nias/policy.hh"
#include "nias/record.hh"

namespace nias::win32 {

enum class Disposition {
    continue_execution,  // mutated context is good; resume
    continue_search,     // let the next handler run
    fast_fail,           // terminate now (unrecoverable)
    terminate,           // controlled process exit
};

// recover.cc --------------------------------------------------------------
// Translate a Windows exception into the portable FaultEvent (registers,
// class, fault address, a bounded window over the faulting instruction).
void fill_event(FaultEvent& ev, const EXCEPTION_RECORD& er,
                const CONTEXT& ctx) noexcept;

// Facts needed to pick the recovery mechanism for the faulting RIP.
RuntimeFacts gather_facts(const CONTEXT& ctx) noexcept;

// Execute a RecoveryPlan against the live context. Returns the VEH disposition.
Disposition apply(const RecoveryPlan& p, CONTEXT& ctx) noexcept;

// Walk the stack from `start`, writing {module_base, rva} per frame. Returns
// the number of frames captured.
std::uint16_t capture_backtrace(const CONTEXT& start, FaultRecord::Frame* out,
                                std::uint16_t max) noexcept;

// log.cc ------------------------------------------------------------------
bool log_start(const char* path, std::uint32_t ring_pow2) noexcept;
void log_stop() noexcept;
void log_push(const FaultRecord& rec) noexcept;  // encode + enqueue; never blocks
std::uint64_t log_dropped() noexcept;

}  // namespace nias::win32
