#pragma once

#include <cstdint>

namespace nias {

// Pool of generated "safe return" stubs. Used only as a fallback when a fault
// lands in code with no unwind metadata (JIT, hand-written asm) and the normal
// RtlVirtualUnwind path is unavailable. Generated code lives for the process
// lifetime; the pool owns it.
class StubPool {
public:
    StubPool();
    ~StubPool();

    StubPool(const StubPool&) = delete;
    StubPool& operator=(const StubPool&) = delete;

    // `add rsp, frame_adjust; xor eax, eax; ret`. frame_adjust may be 0.
    // Returns an executable pointer, or nullptr on failure.
    void* make_return_stub(std::uint32_t frame_adjust) noexcept;

    // `xor eax, eax; ret` — callable as `int(*)()`; used by tests.
    void* make_zero_ret() noexcept;

private:
    struct Impl;
    Impl* impl_;
};

}  // namespace nias
