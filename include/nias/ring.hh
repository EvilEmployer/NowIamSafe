#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>

namespace nias {

// Bounded lock-free MPMC queue (Dmitry Vyukov's algorithm). Multiple fault
// handlers (any thread) push; the single drain thread pops. No allocation and
// no locks on push, which is what the hot path requires.
//
// Capacity must be a power of two. Each slot carries a fixed-size byte blob so
// the queue never touches the heap after construction.
template <std::size_t SlotBytes>
class ByteRing {
public:
    struct Slot {
        std::uint32_t len;
        std::uint8_t bytes[SlotBytes];
    };

    explicit ByteRing(std::size_t capacity_pow2)
        : mask_(capacity_pow2 - 1),
          cells_(std::make_unique<Cell[]>(capacity_pow2)) {
        // Power-of-two check; a non-power-of-two mask would corrupt indexing.
        if (capacity_pow2 == 0 || (capacity_pow2 & mask_) != 0) {
            std::abort();
        }
        for (std::size_t i = 0; i < capacity_pow2; ++i) {
            cells_[i].seq.store(i, std::memory_order_relaxed);
        }
    }

    // Copies up to SlotBytes from `data`. Returns false when the ring is full.
    bool push(const std::uint8_t* data, std::uint32_t len) noexcept {
        if (len > SlotBytes) {
            return false;
        }
        Cell* cell;
        std::size_t pos = enqueue_.load(std::memory_order_relaxed);
        for (;;) {
            cell = &cells_[pos & mask_];
            const std::size_t seq = cell->seq.load(std::memory_order_acquire);
            const std::intptr_t diff =
                static_cast<std::intptr_t>(seq) - static_cast<std::intptr_t>(pos);
            if (diff == 0) {
                if (enqueue_.compare_exchange_weak(pos, pos + 1,
                                                   std::memory_order_relaxed)) {
                    break;
                }
            } else if (diff < 0) {
                return false;  // full
            } else {
                pos = enqueue_.load(std::memory_order_relaxed);
            }
        }
        cell->slot.len = len;
        std::memcpy(cell->slot.bytes, data, len);
        cell->seq.store(pos + 1, std::memory_order_release);
        return true;
    }

    // Copies the next slot into `out`/`out_len`. Returns false when empty.
    bool pop(std::uint8_t* out, std::uint32_t& out_len) noexcept {
        Cell* cell;
        std::size_t pos = dequeue_.load(std::memory_order_relaxed);
        for (;;) {
            cell = &cells_[pos & mask_];
            const std::size_t seq = cell->seq.load(std::memory_order_acquire);
            const std::intptr_t diff = static_cast<std::intptr_t>(seq) -
                                       static_cast<std::intptr_t>(pos + 1);
            if (diff == 0) {
                if (dequeue_.compare_exchange_weak(pos, pos + 1,
                                                   std::memory_order_relaxed)) {
                    break;
                }
            } else if (diff < 0) {
                return false;  // empty
            } else {
                pos = dequeue_.load(std::memory_order_relaxed);
            }
        }
        out_len = cell->slot.len;
        std::memcpy(out, cell->slot.bytes, cell->slot.len);
        cell->seq.store(pos + mask_ + 1, std::memory_order_release);
        return true;
    }

private:
    struct alignas(64) Cell {
        std::atomic<std::size_t> seq;
        Slot slot;
    };

    const std::size_t mask_;
    std::unique_ptr<Cell[]> cells_;
    alignas(64) std::atomic<std::size_t> enqueue_{0};
    alignas(64) std::atomic<std::size_t> dequeue_{0};
};

}  // namespace nias
