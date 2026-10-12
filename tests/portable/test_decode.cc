#include <doctest/doctest.h>

#include <Zydis/Zydis.h>

#include <cstdint>
#include <cstring>

#include "nias/decode.hh"

using namespace nias;

TEST_CASE("decode: mov eax, [rcx] (the canonical null-deref load)") {
    const std::uint8_t code[] = {0x8B, 0x01};  // mov eax, dword ptr [rcx]
    const DecodeInfo d = decode_at(code, sizeof(code), 0x140001000ull);
    REQUIRE(d.valid);
    CHECK(d.length == 2);
    CHECK(d.reads_memory);
    CHECK_FALSE(d.writes_memory);
    CHECK(d.mem_base_reg == static_cast<std::int32_t>(ZYDIS_REGISTER_RCX));
    CHECK(std::strcmp(d.mnemonic, "mov") == 0);
}

TEST_CASE("decode: mov [rax], edx is a store") {
    const std::uint8_t code[] = {0x89, 0x10};  // mov dword ptr [rax], edx
    const DecodeInfo d = decode_at(code, sizeof(code), 0);
    REQUIRE(d.valid);
    CHECK(d.writes_memory);
    CHECK(d.mem_base_reg == static_cast<std::int32_t>(ZYDIS_REGISTER_RAX));
}

TEST_CASE("decode: control-flow classification") {
    const std::uint8_t ret_[] = {0xC3};
    const DecodeInfo r = decode_at(ret_, sizeof(ret_), 0);
    REQUIRE(r.valid);
    CHECK(r.is_ret);
    CHECK(r.is_branch);
    CHECK(r.length == 1);

    const std::uint8_t call_[] = {0xFF, 0xD0};  // call rax
    const DecodeInfo c = decode_at(call_, sizeof(call_), 0);
    REQUIRE(c.valid);
    CHECK(c.is_call);
    CHECK(c.is_branch);

    const std::uint8_t jmp_[] = {0xEB, 0x00};  // jmp +0
    const DecodeInfo j = decode_at(jmp_, sizeof(jmp_), 0);
    REQUIRE(j.valid);
    CHECK(j.is_branch);
    CHECK_FALSE(j.is_call);
}

TEST_CASE("decode: empty / garbage input is not valid") {
    CHECK_FALSE(decode_at(nullptr, 0, 0).valid);
    const std::uint8_t junk[] = {0x00};  // add [rax],al needs 2 bytes
    CHECK_FALSE(decode_at(junk, 1, 0).valid);
}

TEST_CASE("scan_prologue_alloc: push rbp; sub rsp, 0x20 => 40 bytes") {
    // 55                push rbp
    // 48 83 EC 20       sub  rsp, 0x20
    const std::uint8_t prologue[] = {0x55, 0x48, 0x83, 0xEC, 0x20};
    CHECK(scan_prologue_alloc(prologue, sizeof(prologue)) == 8u + 0x20u);
}

TEST_CASE("scan_prologue_alloc: stops at the first non-prologue instruction") {
    // 48 83 EC 10       sub rsp, 0x10
    // C3                ret   (stops here)
    const std::uint8_t code[] = {0x48, 0x83, 0xEC, 0x10, 0xC3};
    CHECK(scan_prologue_alloc(code, sizeof(code)) == 0x10u);
}

TEST_CASE("find_function_start locates the int3 boundary + sizes the frame") {
    // 90           tail of previous function
    // CC CC        int3 padding
    // 55 48 83 EC 20   push rbp; sub rsp, 0x20   (function starts at index 3)
    // 8B 01            mov eax, [rcx]            (fault site, index 8)
    const std::uint8_t buf[] = {0x90, 0xCC, 0xCC, 0x55, 0x48,
                                0x83, 0xEC, 0x20, 0x8B, 0x01};
    const auto start = find_function_start(buf, sizeof(buf), 8, 64);
    REQUIRE(start.has_value());
    CHECK(*start == 3);
    CHECK(scan_prologue_alloc(buf + *start, sizeof(buf) - *start) == 8u + 0x20u);
}

TEST_CASE("find_function_start: nullopt when no padding is in range") {
    const std::uint8_t no_pad[] = {0x55, 0x48, 0x83, 0xEC, 0x20, 0x8B, 0x01};
    CHECK_FALSE(find_function_start(no_pad, sizeof(no_pad), 6, 64).has_value());

    const std::uint8_t pad_far[] = {0xCC, 0x55, 0x48, 0x83, 0xEC, 0x20, 0x8B, 0x01};
    CHECK_FALSE(find_function_start(pad_far, sizeof(pad_far), 7, 2).has_value());
    REQUIRE(find_function_start(pad_far, sizeof(pad_far), 7, 64).has_value());
    CHECK(find_function_start(pad_far, sizeof(pad_far), 7, 64).value() == 1);
}
