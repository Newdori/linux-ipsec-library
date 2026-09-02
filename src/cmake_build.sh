#!/usr/bin/env sh

set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUILD_ROOT="${SCRIPT_DIRECTORY}/.build/cmake"
LIBRARY_ROOT="${SCRIPT_DIRECTORY}/../lib"
APPLICATION_ROOT="${SCRIPT_DIRECTORY}/../app/bin"
IPSEC_BUILD_APP="${IPSEC_BUILD_APP:-ON}"
BUILD_TARGET="all"
BUILD_TARGET_SET="false"

ShowUsage()
{
    printf '%s\n' "Usage: $0 [all|host|zynqmp|clean] [--app|--no-app]"
    printf '%s\n' "       IPSEC_BUILD_APP=ON|OFF $0 [all|host|zynqmp|clean]"
}

ParseArguments()
{
    for ARGUMENT in "$@"; do
        case "${ARGUMENT}" in
        all|host|zynqmp|clean)
            if [ "true" = "${BUILD_TARGET_SET}" ]; then
                printf '%s\n' "Only one build target may be specified." >&2
                ShowUsage >&2
                exit 1
            fi
            BUILD_TARGET="${ARGUMENT}"
            BUILD_TARGET_SET="true"
            ;;
        --app)
            IPSEC_BUILD_APP="ON"
            ;;
        --no-app)
            IPSEC_BUILD_APP="OFF"
            ;;
        --help|-h)
            ShowUsage
            exit 0
            ;;
        *)
            printf '%s\n' "Unknown option: ${ARGUMENT}" >&2
            ShowUsage >&2
            exit 1
            ;;
        esac
    done

    case "${IPSEC_BUILD_APP}" in
    ON|OFF)
        ;;
    *)
        printf '%s\n' "IPSEC_BUILD_APP must be ON or OFF." >&2
        exit 1
        ;;
    esac
}

CopyApplication()
{
    BUILD_DIRECTORY="$1"
    ARCHITECTURE="$2"

    if [ "ON" = "${IPSEC_BUILD_APP}" ]; then
        mkdir -p "${APPLICATION_ROOT}/${ARCHITECTURE}"
        cp "${BUILD_DIRECTORY}/bin/ipsec_app" \
            "${APPLICATION_ROOT}/${ARCHITECTURE}/ipsec_app"
    fi
}

BuildHost()
{
    BUILD_DIRECTORY="${BUILD_ROOT}/host"
    cmake -S "${SCRIPT_DIRECTORY}" -B "${BUILD_DIRECTORY}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DIPSEC_BUILD_TESTS=ON -DIPSEC_BUILD_APP="${IPSEC_BUILD_APP}"
    cmake --build "${BUILD_DIRECTORY}" --parallel
    ctest --test-dir "${BUILD_DIRECTORY}" --output-on-failure
    mkdir -p "${LIBRARY_ROOT}/x86_64"
    cp -P "${BUILD_DIRECTORY}/lib/"libipsecctrl.* "${LIBRARY_ROOT}/x86_64/"
    CopyApplication "${BUILD_DIRECTORY}" "x86_64"
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
        -DIPSEC_BUILD_TESTS=OFF -DIPSEC_BUILD_APP="${IPSEC_BUILD_APP}"
    cmake --build "${BUILD_DIRECTORY}" --parallel
    mkdir -p "${LIBRARY_ROOT}/zynqmp"
    cp -P "${BUILD_DIRECTORY}/lib/"libipsecctrl.* "${LIBRARY_ROOT}/zynqmp/"
    CopyApplication "${BUILD_DIRECTORY}" "zynqmp"
    rm -rf "${BUILD_DIRECTORY}"
}

CleanBuild()
{
    rm -rf "${SCRIPT_DIRECTORY}/.build"
    rm -rf "${LIBRARY_ROOT}/x86_64" "${LIBRARY_ROOT}/zynqmp"
    rm -f "${APPLICATION_ROOT}/x86_64/ipsec_app" "${APPLICATION_ROOT}/zynqmp/ipsec_app"
}

ParseArguments "$@"

case "${BUILD_TARGET}" in
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
