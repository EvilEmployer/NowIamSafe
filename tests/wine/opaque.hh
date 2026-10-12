#pragma once

// Optimizer barriers kept in a separate translation unit so (without LTO) the
// caller cannot prove the laundered value. This lets the harness force a real
// null dereference / divide-by-zero at runtime, portably across MSVC and
// clang/gcc, without inline asm or compiler-specific attributes on the body.
namespace harness {

int* launder_ptr(int* p);
int launder_int(int v);
void use(const void* p);

}  // namespace harness

#if defined(_MSC_VER)
#define NIAS_NOINLINE __declspec(noinline)
#else
#define NIAS_NOINLINE __attribute__((noinline))
#endif
