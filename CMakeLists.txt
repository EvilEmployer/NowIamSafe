cmake_minimum_required(VERSION 3.26)
project(nias LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# C++26 (-std=c++2c), and it is a hard requirement, not a flavour: the code uses
# C++26 constructs (e.g. P2573 `= delete("reason")`) that older modes reject.
# Needs clang >= 19 (CI pins clang 20 on every leg); reflection (P2996) is not in
# any released clang, so it is deliberately not used — see docs/DESIGN.md.
set(NIAS_CXX_STANDARD "26" CACHE STRING "C++ standard; 26 is required, not a floor")
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
