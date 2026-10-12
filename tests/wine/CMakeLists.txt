add_executable(nias_fault_injection fault_injection.cc)
target_link_libraries(nias_fault_injection PRIVATE nias_core)
target_compile_options(nias_fault_injection PRIVATE -Wall -Wextra)

# Registered for completeness; CI runs it through wine64 (see ci workflow).
add_test(NAME wine_fault_injection COMMAND nias_fault_injection)
