include(FetchContent)

# ---- Zydis (bundles the zycore submodule) ------------------------------------
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
FetchContent_Declare(zydis
  GIT_REPOSITORY https://github.com/zyantific/zydis
  GIT_TAG v4.1.1
  GIT_SHALLOW TRUE)

# ---- asmjit ------------------------------------------------------------------
set(ASMJIT_STATIC ON CACHE BOOL "" FORCE)
set(ASMJIT_NO_INSTALL ON CACHE BOOL "" FORCE)
FetchContent_Declare(asmjit
  GIT_REPOSITORY https://github.com/asmjit/asmjit
  GIT_TAG 0d7f01052f2d3f6d6b9bb6714ef32bd7b80177eb)

# ---- doctest -----------------------------------------------------------------
set(DOCTEST_WITH_TESTS OFF CACHE BOOL "" FORCE)
set(DOCTEST_NO_INSTALL ON CACHE BOOL "" FORCE)
FetchContent_Declare(doctest
  GIT_REPOSITORY https://github.com/doctest/doctest
  GIT_TAG v2.5.3
  GIT_SHALLOW TRUE)

FetchContent_MakeAvailable(zydis asmjit doctest)

# Keep third-party warnings out of our -Wpedantic builds.
foreach(_dep Zydis asmjit)
  if(TARGET ${_dep})
    get_target_property(_inc ${_dep} INTERFACE_INCLUDE_DIRECTORIES)
    if(_inc)
      set_target_properties(${_dep} PROPERTIES
        INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_inc}")
    endif()
  endif()
endforeach()
