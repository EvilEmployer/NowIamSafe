add_library(nias_core STATIC
  portable/policy.cc
  portable/record.cc
  portable/decode.cc
  portable/stub.cc)

target_include_directories(nias_core PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(nias_core PUBLIC Zydis asmjit::asmjit)
target_compile_options(nias_core PRIVATE -Wall -Wextra -Wpedantic)

if(NIAS_BUILD_WIN32)
  enable_language(ASM)
  target_sources(nias_core PRIVATE
    win32/recover.cc
    win32/log.cc
    win32/veh.cc
    win32/safepoint.cc
    win32/kued.cc
    win32/kued_thunk.S)
  target_include_directories(nias_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/win32)
  # ntdll for RtlVirtualUnwind / RtlLookupFunctionEntry / RtlPcToFileHeader.
  target_link_libraries(nias_core PUBLIC ntdll)
endif()
