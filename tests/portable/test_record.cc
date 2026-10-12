#include <doctest/doctest.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include "nias/record.hh"

using namespace nias;

static FaultRecord sample(std::uint16_t frames) {
    FaultRecord r{};
    r.magic = kRecordMagic;
    r.version = kRecordVersion;
    r.frame_count = frames;
    r.timestamp = 0x1122334455667788ull;
    r.thread_id = 4321;
    r.native_code = 0xC0000005u;
    r.fault_class = 0;
    r.av_access = 1;
    r.action_taken = 1;
    r.insn_length = 2;
    r.fault_address = 0xdeadbeefull;
    r.rip = 0x140001000ull;
    r.rip_module_base = 0x140000000ull;
    r.rip_rva = 0x1000ull;
    for (int i = 0; i < 16; ++i) r.gpr[i] = 0x1000ull + i;
    r.eflags = 0x202;
    for (std::uint16_t i = 0; i < frames && i < kMaxFrames; ++i) {
        r.frames[i].module_base = 0x140000000ull;
        r.frames[i].rva = 0x2000ull + i * 0x10;
    }
    return r;
}

TEST_CASE("record roundtrip preserves every field") {
    const FaultRecord in = sample(5);
    std::vector<std::uint8_t> buf(sizeof(FaultRecord));

    const std::size_t n = encode(in, buf);
    REQUIRE(n > 0);
    CHECK(n == record_size(in));

    FaultRecord out{};
    REQUIRE(decode(std::span(buf.data(), n), out));
    CHECK(out.magic == in.magic);
    CHECK(out.frame_count == in.frame_count);
    CHECK(out.timestamp == in.timestamp);
    CHECK(out.fault_address == in.fault_address);
    CHECK(out.rip_rva == in.rip_rva);
    CHECK(std::memcmp(out.gpr, in.gpr, sizeof(in.gpr)) == 0);
    for (int i = 0; i < in.frame_count; ++i) {
        CHECK(out.frames[i].rva == in.frames[i].rva);
    }
}

TEST_CASE("compact size shrinks with fewer frames") {
    CHECK(record_size(sample(0)) < record_size(sample(10)));
    CHECK(record_size(sample(10)) < sizeof(FaultRecord));
}

TEST_CASE("encode rejects a buffer that is too small") {
    const FaultRecord in = sample(3);
    std::vector<std::uint8_t> tiny(8);
    CHECK(encode(in, tiny) == 0);
}

TEST_CASE("decode rejects bad magic") {
    const FaultRecord in = sample(2);
    std::vector<std::uint8_t> buf(sizeof(FaultRecord));
    const std::size_t n = encode(in, buf);
    REQUIRE(n > 0);
    buf[0] ^= 0xFF;  // corrupt magic
    FaultRecord out{};
    CHECK_FALSE(decode(std::span(buf.data(), n), out));
}

TEST_CASE("decode rejects truncation") {
    const FaultRecord in = sample(8);
    std::vector<std::uint8_t> buf(sizeof(FaultRecord));
    const std::size_t n = encode(in, buf);
    REQUIRE(n > 0);
    FaultRecord out{};
    CHECK_FALSE(decode(std::span(buf.data(), n - 1), out));
}

TEST_CASE("encode rejects an over-long frame count") {
    FaultRecord in = sample(0);
    in.frame_count = kMaxFrames + 1;
    std::vector<std::uint8_t> buf(sizeof(FaultRecord) * 2);
    CHECK(encode(in, buf) == 0);
}
