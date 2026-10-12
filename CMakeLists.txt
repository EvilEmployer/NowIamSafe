cmake_minimum_required(VERSION 3.26)
project(nias LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# C++26 (-std=c++2c). clang 18+ compiles everything here in c++2c mode; the
# code stays within features current clang actually implements (no reflection
# in the tree yet — see docs/DESIGN.md). Override for an older compiler with
# -DNIAS_CXX_STANDARD=20.
set(NIAS_CXX_STANDARD "26" CACHE STRING "C++ standard (26 default; 20 floor)")
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
