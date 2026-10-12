// Integration harness (L2): builds for x86_64-w64-mingw32 and runs under
// wine64. It triggers real hardware faults in a live process and asserts that
// the VEH layer recovers each one and logs a decodable record. This is the
// end-to-end proof that the Win32 layer works, not a mock.

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

#include "nias/nias.hh"
#include "nias/record.hh"

namespace {

int g_checks = 0;
int g_fails = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        ++g_checks;                                                       \
        if (!(cond)) {                                                    \
            ++g_fails;                                                    \
            std::printf("FAIL  %s  (line %d)\n", #cond, __LINE__);        \
        } else {                                                          \
            std::printf("ok    %s\n", #cond);                            \
        }                                                                 \
    } while (0)

// Keep the optimizer from folding away the faulting code.
void escape(void* p) {
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

// Launder a value so the compiler cannot prove it (dereferencing null or
// dividing by zero is UB; without this the optimizer elides the faulting op
// instead of letting it trap at runtime).
template <class T>
T opaque(T v) {
    __asm__ __volatile__("" : "+r"(v));
    return v;
}

// Non-leaf: a real stack frame and a call, so it carries .pdata and exercises
// the RtlVirtualUnwind path.
__attribute__((noinline)) int deref_nonleaf(volatile int* p) {
    char buf[128];
    for (int i = 0; i < static_cast<int>(sizeof(buf)); ++i) {
        buf[i] = static_cast<char>(i);
    }
    escape(buf);
    return *p + buf[0];  // AV when p == nullptr
}

// Leaf: no frame, no .pdata — exercises the leaf-pop path.
__attribute__((noinline)) int deref_leaf(volatile int* p) { return *p; }

__attribute__((noinline)) int store_null(volatile int* p) {
    *p = 0x55;  // AV write
    // Opaque so the caller actually reloads eax after the call; a constant
    // return would be folded in and hide the sentinel.
    return opaque<int>(7);
}

__attribute__((noinline)) int divide(int a, int b) { return a / b; }  // #DE

std::vector<nias::FaultRecord> read_records(const char* path) {
    std::vector<nias::FaultRecord> out;
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return out;
    }
    for (;;) {
        std::uint32_t len = 0;
        if (!f.read(reinterpret_cast<char*>(&len), sizeof(len))) {
            break;
        }
        std::vector<std::uint8_t> buf(len);
        if (!f.read(reinterpret_cast<char*>(buf.data()), len)) {
            break;
        }
        nias::FaultRecord rec{};
        if (nias::decode(buf.data(), len, rec)) {
            out.push_back(rec);
        }
    }
    return out;
}

}  // namespace

int main(int argc, char** argv) {
    const char* log_path = (argc > 1) ? argv[1] : "nias_fault.log";

    nias::Config cfg;
    cfg.log_path = log_path;
    cfg.backtrace_depth = 16;
    CHECK(nias::init(cfg));

    const int r1 = deref_nonleaf(opaque<volatile int*>(nullptr));
    std::printf("[harness] survived non-leaf AV, returned %d\n", r1);
    CHECK(r1 == 0);  // sentinel return

    const int r2 = deref_leaf(opaque<volatile int*>(nullptr));
    std::printf("[harness] survived leaf AV, returned %d\n", r2);
    CHECK(r2 == 0);

    const int r3 = store_null(opaque<volatile int*>(nullptr));
    std::printf("[harness] survived AV write, returned %d\n", r3);
    CHECK(r3 == 0);

    const int r4 = divide(42, opaque<int>(0));
    std::printf("[harness] survived divide-by-zero, returned %d\n", r4);
    CHECK(r4 == 0);

    const nias::Stats st = nias::stats();
    std::printf("[harness] stats: faults=%llu recovered=%llu passed=%llu dropped=%llu\n",
                (unsigned long long)st.faults_seen, (unsigned long long)st.recovered,
                (unsigned long long)st.passed_through,
                (unsigned long long)st.dropped_records);
    CHECK(st.faults_seen >= 4);
    CHECK(st.recovered >= 4);
    CHECK(st.dropped_records == 0);

    nias::shutdown();  // flushes the drain thread and closes the file

    const std::vector<nias::FaultRecord> recs = read_records(log_path);
    std::printf("[harness] decoded %zu records from %s\n", recs.size(), log_path);
    CHECK(recs.size() >= 4);

    bool saw_av = false;
    bool saw_divide = false;
    for (const auto& r : recs) {
        CHECK(r.magic == nias::kRecordMagic);
        CHECK(r.rip != 0);
        CHECK(r.rip_module_base != 0);  // RtlPcToFileHeader resolved our image
        CHECK(r.frame_count >= 1);
        if (r.fault_class == static_cast<std::uint8_t>(nias::FaultClass::access_violation)) {
            saw_av = true;
            CHECK(r.fault_address == 0);  // null deref
        }
        if (r.fault_class == static_cast<std::uint8_t>(nias::FaultClass::divide_by_zero)) {
            saw_divide = true;
        }
    }
    CHECK(saw_av);
    CHECK(saw_divide);

    std::printf("\n=== %d checks, %d failures ===\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
