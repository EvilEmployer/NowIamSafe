#include <doctest/doctest.h>

#include <cstdint>
#include <cstring>

#include "nias/decode.hh"
#include "nias/stub.hh"

using namespace nias;

TEST_CASE("make_zero_ret is callable and returns 0") {
    StubPool pool;
    void* p = pool.make_zero_ret();
    REQUIRE(p != nullptr);
    auto fn = reinterpret_cast<int (*)()>(p);
    CHECK(fn() == 0);
}

// The return stub adjusts RSP, so it can't be called as an ordinary function;
// instead disassemble its bytes with Zydis and assert the exact sequence
// `add rsp, N; xor eax, eax; ret`. This cross-checks the asmjit emitter.
TEST_CASE("make_return_stub emits add rsp,N / xor eax,eax / ret") {
    StubPool pool;
    void* p = pool.make_return_stub(0x20);
    REQUIRE(p != nullptr);
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(p);

    std::size_t off = 0;
    const DecodeInfo a = decode_at(bytes + off, 16, 0);
    REQUIRE(a.valid);
    CHECK(std::strcmp(a.mnemonic, "add") == 0);
    off += a.length;

    const DecodeInfo x = decode_at(bytes + off, 16, 0);
    REQUIRE(x.valid);
    CHECK(std::strcmp(x.mnemonic, "xor") == 0);
    off += x.length;

    const DecodeInfo r = decode_at(bytes + off, 16, 0);
    REQUIRE(r.valid);
    CHECK(r.is_ret);
}

TEST_CASE("make_return_stub(0) omits the add") {
    StubPool pool;
    void* p = pool.make_return_stub(0);
    REQUIRE(p != nullptr);
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(p);
    const DecodeInfo first = decode_at(bytes, 16, 0);
    REQUIRE(first.valid);
    CHECK(std::strcmp(first.mnemonic, "xor") == 0);
}
