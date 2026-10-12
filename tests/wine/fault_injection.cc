// Integration harness (L2): builds for x86_64-w64-mingw32 and runs under
// wine64. It triggers real hardware faults in a live process and asserts that
// the VEH layer recovers each one and logs a decodable record. This is the
// end-to-end proof that the Win32 layer works, not a mock.

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <span>
#include <vector>

#include "nias/nias.hh"
#include "nias/record.hh"
#include "opaque.hh"

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

// Non-leaf: a real stack frame and a call, so it carries .pdata and exercises
// the RtlVirtualUnwind path.
NIAS_NOINLINE int deref_nonleaf(int* p) {
    char buf[128];
    for (int i = 0; i < static_cast<int>(sizeof(buf)); ++i) {
        buf[i] = static_cast<char>(i);
    }
    harness::use(buf);
    return *p + buf[0];  // AV when p == nullptr
}

// Leaf: no frame, no .pdata — exercises the leaf-pop path.
NIAS_NOINLINE int deref_leaf(int* p) { return *p; }

NIAS_NOINLINE int store_null(int* p) {
    *p = 0x55;  // AV write
    // Opaque return so the caller actually reloads the result register; a
    // constant return would be folded in and hide the sentinel.
    return harness::launder_int(7);
}

NIAS_NOINLINE int divide(int a, int b) { return a / b; }  // #DE

// A framed function with NO unwind metadata: raw machine code in executable
// memory (no .pdata, no dynamic function table), preceded by int3 padding so
// the function-start heuristic can anchor the prologue scan. It allocates a
// frame with `sub rsp,0x28` (no saved non-volatiles), so the stub recovery
// `add rsp,0x28; ret` returns to the caller cleanly. Exercises stub_redirect.
int run_stub_path() {
    const unsigned char code[] = {
        0xCC, 0xCC, 0xCC, 0xCC,        // int3 padding -> function-start boundary
        0x48, 0x83, 0xEC, 0x28,        // sub rsp, 0x28   (frame, no pushes)
        0x48, 0x31, 0xC0,              // xor rax, rax
        0x8B, 0x00,                    // mov eax, [rax]  -> AV at null
        0x48, 0x83, 0xC4, 0x28,        // add rsp, 0x28   (epilogue, unreached)
        0xC3,                          // ret
    };
    void* mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);
    if (mem == nullptr) {
        return -1;
    }
    std::memcpy(mem, code, sizeof(code));
    DWORD old = 0;
    VirtualProtect(mem, 0x1000, PAGE_EXECUTE_READ, &old);

    auto fn = reinterpret_cast<int (*)()>(static_cast<unsigned char*>(mem) + 4);
    const int r = fn();  // faults; stub recovery returns here with eax = 0
    // mem intentionally leaked (process-lifetime executable page)
    return r;
}

// Register a safe-point, fault inside a nested call under unwind_to_safepoint
// policy, and verify execution resumes at the safe-point (not one frame up).
NIAS_NOINLINE int run_safepoint() {
    nias::set_policy(nias::FaultClass::access_violation,
                     nias::Action::unwind_to_safepoint);

    volatile int result = 0;
    nias_safepoint sp;
    if (nias_safepoint_set(&sp) == 0) {
        result = deref_leaf(harness::launder_ptr(nullptr));  // faults -> unwinds to else
        nias_safepoint_clear(&sp);
    } else {
        result = 42;  // resumed here via RtlRestoreContext
    }

    nias::set_policy(nias::FaultClass::access_violation, nias::Action::unwind_one);
    return result;
}

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
        if (nias::decode(std::span(buf.data(), len), rec)) {
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

    const int r1 = deref_nonleaf(harness::launder_ptr(nullptr));
    std::printf("[harness] survived non-leaf AV, returned %d\n", r1);
    CHECK(r1 == 0);  // sentinel return

    const int r2 = deref_leaf(harness::launder_ptr(nullptr));
    std::printf("[harness] survived leaf AV, returned %d\n", r2);
    CHECK(r2 == 0);

    const int r3 = store_null(harness::launder_ptr(nullptr));
    std::printf("[harness] survived AV write, returned %d\n", r3);
    CHECK(r3 == 0);

    const int r4 = divide(42, harness::launder_int(0));
    std::printf("[harness] survived divide-by-zero, returned %d\n", r4);
    CHECK(r4 == 0);

    const int r5 = run_stub_path();
    std::printf("[harness] survived no-.pdata framed AV (stub), returned %d\n", r5);
    CHECK(r5 == 0);

    const int r6 = run_safepoint();
    std::printf("[harness] recovered to safe-point, returned %d\n", r6);
    CHECK(r6 == 42);

    const nias::Stats st = nias::stats();
    std::printf("[harness] stats: faults=%llu recovered=%llu passed=%llu dropped=%llu\n",
                (unsigned long long)st.faults_seen, (unsigned long long)st.recovered,
                (unsigned long long)st.passed_through,
                (unsigned long long)st.dropped_records);
    CHECK(st.faults_seen >= 6);
    CHECK(st.recovered >= 6);
    CHECK(st.dropped_records == 0);

    nias::shutdown();  // flushes the drain thread and closes the file

    const std::vector<nias::FaultRecord> recs = read_records(log_path);
    std::printf("[harness] decoded %zu records from %s\n", recs.size(), log_path);
    CHECK(recs.size() >= 6);

    bool saw_av = false;
    bool saw_divide = false;
    bool saw_stub = false;
    bool saw_safepoint = false;
    bool saw_module = false;
    for (const auto& r : recs) {
        CHECK(r.magic == nias::kRecordMagic);
        CHECK(r.rip != 0);
        CHECK(r.frame_count >= 1);
        if (r.rip_module_base != 0) {
            saw_module = true;  // RtlPcToFileHeader resolved a loaded image
        }
        if (r.fault_class == static_cast<std::uint8_t>(nias::FaultClass::access_violation)) {
            saw_av = true;
            CHECK(r.fault_address == 0);  // null deref
        }
        if (r.fault_class == static_cast<std::uint8_t>(nias::FaultClass::divide_by_zero)) {
            saw_divide = true;
        }
        if (r.action_taken == static_cast<std::uint8_t>(nias::Action::stub_redirect)) {
            saw_stub = true;
        }
        if (r.action_taken == static_cast<std::uint8_t>(nias::Action::unwind_to_safepoint)) {
            saw_safepoint = true;
        }
    }
    CHECK(saw_av);
    CHECK(saw_divide);
    CHECK(saw_stub);       // no-.pdata framed fault took the stub path
    CHECK(saw_safepoint);  // safe-point fault logged its action
    CHECK(saw_module);     // module-resident faults resolved a base

    std::printf("\n=== %d checks, %d failures ===\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
