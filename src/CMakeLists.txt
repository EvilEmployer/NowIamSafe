add_library(nias_core STATIC
  portable/policy.cc
  portable/record.cc
  portable/decode.cc
  portable/stub.cc)

target_include_directories(nias_core PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(nias_core PUBLIC Zydis asmjit::asmjit)
target_compile_options(nias_core PRIVATE -Wall -Wextra -Wpedantic)

# Win32 VEH layer (M2) — sources added here once implemented.
# if(NIAS_BUILD_WIN32)
#   target_sources(nias_core PRIVATE win32/veh_source.cc win32/unwind.cc win32/bootstrap.cc)
# endif()
