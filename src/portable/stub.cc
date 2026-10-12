#include "nias/stub.hh"

#include <asmjit/core.h>
#include <asmjit/x86.h>

namespace nias {

struct StubPool::Impl {
    asmjit::JitRuntime rt;
};

StubPool::StubPool() : impl_(new Impl()) {}

StubPool::~StubPool() { delete impl_; }

namespace {

void* emit(asmjit::JitRuntime& rt, std::uint32_t frame_adjust) noexcept {
    using namespace asmjit;
    CodeHolder code;
    if (code.init(rt.environment(), rt.cpu_features()) != kErrorOk) {
        return nullptr;
    }
    x86::Assembler a(&code);
    if (frame_adjust != 0) {
        a.add(x86::rsp, imm(frame_adjust));
    }
    a.xor_(x86::eax, x86::eax);
    a.ret();

    void* fn = nullptr;
    if (rt.add(&fn, &code) != kErrorOk) {
        return nullptr;
    }
    return fn;
}

}  // namespace

void* StubPool::make_return_stub(std::uint32_t frame_adjust) noexcept {
    return emit(impl_->rt, frame_adjust);
}

void* StubPool::make_zero_ret() noexcept { return emit(impl_->rt, 0); }

}  // namespace nias
