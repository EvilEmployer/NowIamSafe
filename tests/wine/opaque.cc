#include "opaque.hh"

namespace harness {

namespace {
volatile int g_sink = 0;
}

// Identity, but opaque to the caller's optimizer across TU boundaries.
int* launder_ptr(int* p) { return p; }
int launder_int(int v) { return v; }

void use(const void* p) { g_sink = static_cast<int>(reinterpret_cast<unsigned long long>(p)); }

}  // namespace harness
