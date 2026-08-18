#!/usr/bin/env sh

set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUILD_ROOT="${SCRIPT_DIRECTORY}/.build/cmake"
LIBRARY_ROOT="${SCRIPT_DIRECTORY}/../lib"

ShowUsage()
{
    printf '%s\n' "Usage: $0 [all|host|zynqmp|clean]"
}

BuildHost()
{
    BUILD_DIRECTORY="${BUILD_ROOT}/host"
    cmake -S "${SCRIPT_DIRECTORY}" -B "${BUILD_DIRECTORY}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DIPSEC_BUILD_TESTS=ON
    cmake --build "${BUILD_DIRECTORY}" --parallel
    ctest --test-dir "${BUILD_DIRECTORY}" --output-on-failure
    mkdir -p "${LIBRARY_ROOT}/x86_64"
    cp "${BUILD_DIRECTORY}/lib/libipsec.a" "${LIBRARY_ROOT}/x86_64/libipsec.a"
    cp "${BUILD_DIRECTORY}/lib/libipsec.so" "${LIBRARY_ROOT}/x86_64/libipsec.so"
    rm -rf "${BUILD_DIRECTORY}"
}

BuildZynqmp()
{
    BUILD_DIRECTORY="${BUILD_ROOT}/zynqmp"
    COMPILER="${ZYNQMP_CC:-aarch64-linux-gnu-gcc}"
    cmake -S "${SCRIPT_DIRECTORY}" -B "${BUILD_DIRECTORY}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_SYSTEM_NAME=Linux \
        -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
        -DCMAKE_C_COMPILER="${COMPILER}" \
        -DIPSEC_BUILD_TESTS=OFF
    cmake --build "${BUILD_DIRECTORY}" --parallel
    mkdir -p "${LIBRARY_ROOT}/zynqmp"
    cp "${BUILD_DIRECTORY}/lib/libipsec.a" "${LIBRARY_ROOT}/zynqmp/libipsec.a"
    cp "${BUILD_DIRECTORY}/lib/libipsec.so" "${LIBRARY_ROOT}/zynqmp/libipsec.so"
    rm -rf "${BUILD_DIRECTORY}"
}

CleanBuild()
{
    rm -rf "${SCRIPT_DIRECTORY}/.build"
    rm -rf "${LIBRARY_ROOT}/x86_64" "${LIBRARY_ROOT}/zynqmp"
}

case "${1:-all}" in
all)
    BuildHost
    BuildZynqmp
    ;;
host)
    BuildHost
    ;;
zynqmp)
    BuildZynqmp
    ;;
clean)
    CleanBuild
    ;;
*)
    ShowUsage
    exit 1
    ;;
esac
