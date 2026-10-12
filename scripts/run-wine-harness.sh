#!/usr/bin/env bash
# Cross-build the fault-injection harness to mingw-w64 and run it under wine64,
# then decode the emitted log. This is the local L2 loop (see docs/DESIGN.md).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
build="$root/build-wine"

cmake -S "$root" -B "$build" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$root/cmake/toolchain-mingw-clang.cmake" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build "$build" -j"$(nproc)"

export WINEPREFIX="${WINEPREFIX:-$build/.wineprefix}"
export WINEDEBUG="${WINEDEBUG:--all}"
wine="$(command -v wine64 || echo /usr/lib/wine/wine64)"

"$wine" "$build/tests/wine/nias_fault_injection.exe" "$build/nias_fault.log"

echo "--- decoding $build/nias_fault.log ---"
python3 "$root/tools/symbolize/nias_symbolize.py" "$build/nias_fault.log"
