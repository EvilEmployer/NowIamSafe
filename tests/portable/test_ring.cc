#include <doctest/doctest.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <thread>
#include <unordered_set>
#include <vector>

#include "nias/ring.hh"

using namespace nias;

namespace {
constexpr std::size_t kSlot = 64;
using Ring = ByteRing<kSlot>;

std::uint64_t get_u64(const std::uint8_t* p) {
    std::uint64_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}
void put_u64(std::uint8_t* p, std::uint64_t v) { std::memcpy(p, &v, sizeof(v)); }
}  // namespace

TEST_CASE("single-thread FIFO and empty/full edges") {
    Ring ring(4);
    std::uint8_t buf[kSlot];
    std::uint32_t len = 0;

    CHECK_FALSE(ring.pop(buf, len));  // empty

    for (std::uint64_t i = 0; i < 4; ++i) {
        put_u64(buf, i);
        REQUIRE(ring.push(buf, sizeof(std::uint64_t)));
    }
    put_u64(buf, 99);
    CHECK_FALSE(ring.push(buf, sizeof(std::uint64_t)));  // full

    for (std::uint64_t i = 0; i < 4; ++i) {
        REQUIRE(ring.pop(buf, len));
        CHECK(len == sizeof(std::uint64_t));
        CHECK(get_u64(buf) == i);
    }
    CHECK_FALSE(ring.pop(buf, len));
}

TEST_CASE("push rejects oversized payloads") {
    Ring ring(2);
    std::vector<std::uint8_t> big(kSlot + 1, 0xAB);
    CHECK_FALSE(ring.push(big.data(), static_cast<std::uint32_t>(big.size())));
}

TEST_CASE("MPSC: no loss, no duplication under contention") {
    constexpr int kProducers = 4;
    constexpr std::uint64_t kPerProducer = 50000;
    Ring ring(1024);

    std::atomic<bool> start{false};
    std::vector<std::thread> producers;
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([&, p] {
            while (!start.load(std::memory_order_acquire)) {
            }
            std::uint8_t buf[kSlot];
            for (std::uint64_t i = 0; i < kPerProducer; ++i) {
                const std::uint64_t key =
                    (static_cast<std::uint64_t>(p) << 40) | i;
                put_u64(buf, key);
                while (!ring.push(buf, sizeof(std::uint64_t))) {
                    std::this_thread::yield();
                }
            }
        });
    }

    const std::uint64_t total = kProducers * kPerProducer;
    std::unordered_set<std::uint64_t> seen;
    seen.reserve(total);

    std::thread consumer([&] {
        while (!start.load(std::memory_order_acquire)) {
        }
        std::uint8_t buf[kSlot];
        std::uint32_t len = 0;
        std::uint64_t got = 0;
        while (got < total) {
            if (ring.pop(buf, len)) {
                CHECK(seen.insert(get_u64(buf)).second);  // no duplicate
                ++got;
            } else {
                std::this_thread::yield();
            }
        }
    });

    start.store(true, std::memory_order_release);
    for (auto& t : producers) t.join();
    consumer.join();

    CHECK(seen.size() == total);  // no loss
}
