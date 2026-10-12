// v2 integration: install the KiUserExceptionDispatcher hook, trigger one AV,
// and confirm the hook saw it ahead of the VEH chain and recovered. Separate
// from the main harness so a build-specific layout mismatch here cannot mask
// the v1 validation. The analysis results are printed so a mismatch on a given
// Windows build is diagnosable from the CI log.

#include <windows.h>

#include <cstdint>
#include <cstdio>

#include "nias/nias.hh"
#include "opaque.hh"

namespace {
int g_checks = 0;
int g_fails = 0;
}  // namespace

#define CHECK(cond)                                                \
    do {                                                           \
        ++g_checks;                                                \
        if (!(cond)) {                                             \
            ++g_fails;                                             \
            std::printf("FAIL  %s  (line %d)\n", #cond, __LINE__); \
        } else {                                                   \
            std::printf("ok    %s\n", #cond);                      \
        }                                                          \
    } while (0)

NIAS_NOINLINE int deref_leaf(int* p) { return *p; }

int main(int argc, char** argv) {
    const char* log_path = (argc > 1) ? argv[1] : "nias_kued.log";

    // Unbuffered so the diagnostics below survive a crash in the fault path.
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    // Dump the real prologue so a build whose layout analyze doesn't match is
    // diagnosable from the CI log.
    if (HMODULE ntdll = GetModuleHandleA("ntdll.dll")) {
        auto* kued = reinterpret_cast<const unsigned char*>(
            GetProcAddress(ntdll, "KiUserExceptionDispatcher"));
        std::printf("[kued] KiUserExceptionDispatcher=%p\n",
                    reinterpret_cast<const void*>(kued));
        if (kued) {
            std::printf("[kued] prologue:");
            for (int i = 0; i < 48; ++i) {
                std::printf(" %02X", kued[i]);
            }
            std::printf("\n");
        }
    }

    nias::Config cfg;
    cfg.log_path = log_path;
    CHECK(nias::init(cfg));

    const bool ok = nias::install_kued();
    const nias::KuedInfo ki = nias::kued_info();
    std::printf("[kued] install=%d exc_off=0x%X ctx_off=0x%X dispatch=%p\n",
                static_cast<int>(ok), ki.exc_off, ki.ctx_off, ki.dispatch);
    CHECK(ok);

    if (ok) {
        const std::uint64_t before = nias::kued_hits();
        const int r = deref_leaf(harness::launder_ptr(nullptr));  // AV, ahead of VEH
        const std::uint64_t after = nias::kued_hits();
        nias::uninstall_kued();
        std::printf("[kued] recovered r=%d hits %llu->%llu\n", r,
                    static_cast<unsigned long long>(before),
                    static_cast<unsigned long long>(after));
        CHECK(r == 0);
        CHECK(after > before);  // the Kued hook, not the VEH, took the fault
    }

    nias::shutdown();
    std::printf("\n=== %d checks, %d failures ===\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
