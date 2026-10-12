# Cross-compile to Windows x64 with clang + the mingw-w64 sysroot, for running
# the integration harness under wine64. This is the L2 validation path, not the
# authoritative one (LLVM/Clang on real Windows is L3).
#
# The clang binary is overridable via NIAS_CC/NIAS_CXX so CI can pin a version
# (the code is C++26 and needs clang >= 19); defaults to the unversioned driver.
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(_triple x86_64-w64-mingw32)
set(_cc "$ENV{NIAS_CC}")
set(_cxx "$ENV{NIAS_CXX}")
if(NOT _cc)
  set(_cc clang)
endif()
if(NOT _cxx)
  set(_cxx clang++)
endif()
set(CMAKE_C_COMPILER ${_cc})
set(CMAKE_CXX_COMPILER ${_cxx})
set(CMAKE_ASM_COMPILER ${_cc})
set(CMAKE_C_COMPILER_TARGET ${_triple})
set(CMAKE_CXX_COMPILER_TARGET ${_triple})
set(CMAKE_ASM_COMPILER_TARGET ${_triple})
set(CMAKE_RC_COMPILER ${_triple}-windres)

# Static CRT/stdlib so the harness exe runs under wine without chasing DLLs.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static -static-libgcc -static-libstdc++")

set(CMAKE_FIND_ROOT_PATH /usr/${_triple})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
