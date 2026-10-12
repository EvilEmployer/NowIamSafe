#include <atomic>
#include <new>

#include "nias/ring.hh"
#include "win32_internal.hh"

namespace nias::win32 {

namespace {

// A slot must hold the largest possible compact record.
constexpr std::size_t kSlot = sizeof(FaultRecord) + 8;
using Ring = ByteRing<kSlot>;

Ring* g_ring = nullptr;
HANDLE g_file = INVALID_HANDLE_VALUE;
HANDLE g_thread = nullptr;
std::atomic<bool> g_stop{false};
std::atomic<std::uint64_t> g_dropped{0};

void write_record(const std::uint8_t* buf, std::uint32_t len) noexcept {
    if (g_file == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD wrote = 0;
    // Length-prefixed so the offline tool can frame records in the stream.
    WriteFile(g_file, &len, sizeof(len), &wrote, nullptr);
    WriteFile(g_file, buf, len, &wrote, nullptr);
}

DWORD WINAPI drain_main(LPVOID) {
    std::uint8_t buf[kSlot];
    std::uint32_t len = 0;
    for (;;) {
        if (g_ring->pop(buf, len)) {
            write_record(buf, len);
            continue;
        }
        if (g_stop.load(std::memory_order_acquire)) {
            break;  // empty and asked to stop (producers already detached)
        }
        Sleep(1);
    }
    return 0;
}

}  // namespace

bool log_start(const char* path, std::uint32_t ring_pow2) noexcept {
    if (g_ring != nullptr) {
        return true;
    }
    g_dropped.store(0, std::memory_order_relaxed);
    g_stop.store(false, std::memory_order_release);

    g_ring = new (std::nothrow) Ring(ring_pow2 ? ring_pow2 : 1024);
    if (g_ring == nullptr) {
        return false;
    }
    if (path != nullptr) {
        g_file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    g_thread = CreateThread(nullptr, 0, drain_main, nullptr, 0, nullptr);
    if (g_thread == nullptr) {
        delete g_ring;
        g_ring = nullptr;
        return false;
    }
    return true;
}

void log_stop() noexcept {
    if (g_ring == nullptr) {
        return;
    }
    g_stop.store(true, std::memory_order_release);
    if (g_thread != nullptr) {
        WaitForSingleObject(g_thread, INFINITE);
        CloseHandle(g_thread);
        g_thread = nullptr;
    }
    if (g_file != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(g_file);
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
    }
    delete g_ring;
    g_ring = nullptr;
}

void log_push(const FaultRecord& rec) noexcept {
    if (g_ring == nullptr) {
        return;
    }
    std::uint8_t buf[kSlot];
    const std::size_t n = encode(rec, buf);
    if (n == 0 || !g_ring->push(buf, static_cast<std::uint32_t>(n))) {
        g_dropped.fetch_add(1, std::memory_order_relaxed);
    }
}

std::uint64_t log_dropped() noexcept {
    return g_dropped.load(std::memory_order_relaxed);
}

}  // namespace nias::win32
