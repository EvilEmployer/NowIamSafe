cmake_minimum_required(VERSION 3.24)
project(nias LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Floor is C++20: the portable core and Win32 layer are C++20-clean and build
# on clang 18, mingw-g++ 13, MSVC and clang-cl without standard-mapping
# surprises. The clang-24 target bumps this to 26 (-DNIAS_CXX_STANDARD=26).
set(NIAS_CXX_STANDARD "20" CACHE STRING "C++ standard (20 floor; 26 on clang 24)")
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
