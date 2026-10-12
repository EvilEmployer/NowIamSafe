add_executable(nias_fault_injection fault_injection.cc opaque.cc)
target_link_libraries(nias_fault_injection PRIVATE nias_core)
if(NOT MSVC)
  target_compile_options(nias_fault_injection PRIVATE -Wall -Wextra)
endif()

# Run natively on Windows CI and under wine64 on Linux CI.
add_test(NAME integration COMMAND nias_fault_injection)
