add_executable(nias_fault_injection fault_injection.cc opaque.cc)
target_link_libraries(nias_fault_injection PRIVATE nias_core)
if(NOT MSVC)
  target_compile_options(nias_fault_injection PRIVATE -Wall -Wextra)
endif()

# Run natively on Windows CI and under wine64 on Linux CI.
add_test(NAME integration COMMAND nias_fault_injection)

# v2: KiUserExceptionDispatcher hook. Separate so a build-specific layout
# mismatch does not mask the v1 integration test.
add_executable(nias_kued_test kued_test.cc opaque.cc)
target_link_libraries(nias_kued_test PRIVATE nias_core)
if(NOT MSVC)
  target_compile_options(nias_kued_test PRIVATE -Wall -Wextra)
endif()
add_test(NAME kued COMMAND nias_kued_test)
