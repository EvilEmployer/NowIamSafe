# L1: native portable-core tests. Skipped only in the mingw cross build (where
# std::thread brings libstdc++ quirks); they build natively on Linux and MSVC.
if(NOT CMAKE_CROSSCOMPILING)
  find_package(Threads REQUIRED)

  add_executable(nias_portable_tests
    portable/test_main.cc
    portable/test_policy.cc
    portable/test_record.cc
    portable/test_ring.cc
    portable/test_decode.cc
    portable/test_stub.cc)

  target_link_libraries(nias_portable_tests
    PRIVATE nias_core doctest::doctest Threads::Threads)
  target_compile_options(nias_portable_tests PRIVATE -Wall -Wextra)

  add_test(NAME portable COMMAND nias_portable_tests)
endif()

# L2: Windows fault-injection harness (built for mingw, run under wine64).
if(NIAS_BUILD_WIN32)
  add_subdirectory(wine)
endif()
