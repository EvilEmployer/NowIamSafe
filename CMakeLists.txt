cmake_minimum_required(VERSION 3.24)
project(nias LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Portable core and tests build at C++23 (floor that clang 18 / mingw-g++ 13
# handle); the clang-24 CI job bumps this to 26 and adds the module facade.
set(NIAS_CXX_STANDARD "23" CACHE STRING "C++ standard: 23 (portable) or 26 (clang24)")
set(CMAKE_CXX_STANDARD ${NIAS_CXX_STANDARD})
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

option(NIAS_BUILD_TESTS "Build the native portable-core tests" ON)
if(WIN32)
  option(NIAS_BUILD_WIN32 "Build the Win32 VEH layer" ON)
else()
  option(NIAS_BUILD_WIN32 "Build the Win32 VEH layer" OFF)
endif()

include(deps)

add_subdirectory(src)

if(NIAS_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
