#!/bin/sh

set -eu

SERVICE_NAME=${SERVICE_NAME:-}
DRY_RUN=${DRY_RUN:-0}
DISABLE_ON_BOOT=${DISABLE_ON_BOOT:-0}

LogInfo()
{
    printf '%s\n' "$*"
}

LogError()
{
    printf 'ERROR: %s\n' "$*" >&2
}

RunCommand()
{
    if [ "${DRY_RUN}" = "1" ]; then
        printf '+'
        printf ' %s' "$@"
        printf '\n'
    else
        "$@"
    fi
}

RequireRoot()
{
    if [ "${DRY_RUN}" = "1" ]; then
        :
    elif [ "$(id -u)" -ne 0 ]; then
        LogError 'Run this script as root.'
        exit 1
    else
        :
    fi
}

DetectServiceName()
{
    if [ -n "${SERVICE_NAME}" ]; then
        printf '%s\n' "${SERVICE_NAME}"
        return 0
    else
        :
    fi

    if command -v systemctl >/dev/null 2>&1; then
        for pcCandidate in strongswan strongswan-starter strongswan-swanctl ipsec
        do
            if systemctl cat "${pcCandidate}.service" >/dev/null 2>&1; then
                printf '%s\n' "${pcCandidate}"
                return 0
            else
                :
            fi
        done
    else
        :
    fi

    for pcInitScript in \
        /etc/init.d/strongswan \
        /etc/init.d/strongswan-starter \
        /etc/init.d/ipsec
    do
        if [ -x "${pcInitScript}" ]; then
            printf '%s\n' "${pcInitScript}"
            return 0
        else
            :
        fi
    done

    return 1
}

DisableSysvService()
{
    pcInitScript=$1
    pcInitName=${pcInitScript##*/}

    if command -v update-rc.d >/dev/null 2>&1; then
        RunCommand update-rc.d -f "${pcInitName}" remove
    elif command -v chkconfig >/dev/null 2>&1; then
        RunCommand chkconfig "${pcInitName}" off
    else
        LogError 'Cannot disable SysV autostart: update-rc.d/chkconfig was not found.'
        exit 1
    fi
}

StopCharon()
{
    pcDetectedService=$(DetectServiceName || true)

    if [ -z "${pcDetectedService}" ]; then
        LogError 'No supported strongSwan systemd unit or SysV init script was found.'
        LogError 'Set SERVICE_NAME if the image uses a custom unit or init script.'
        exit 1
    else
        :
    fi

    case "${pcDetectedService}" in
        /*)
            RunCommand "${pcDetectedService}" stop
            if [ "${DISABLE_ON_BOOT}" = "1" ]; then
                DisableSysvService "${pcDetectedService}"
            else
                :
            fi
            ;;
        *)
            RunCommand systemctl stop "${pcDetectedService}.service"
            if [ "${DISABLE_ON_BOOT}" = "1" ]; then
                RunCommand systemctl disable "${pcDetectedService}.service"
            else
                :
            fi
            ;;
    esac

    LogInfo "Stopped strongSwan using: ${pcDetectedService}"
}

IsCharonRunning()
{
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -x charon >/dev/null 2>&1 || \
            pgrep -x charon-systemd >/dev/null 2>&1
    elif command -v pidof >/dev/null 2>&1; then
        pidof charon >/dev/null 2>&1 || \
            pidof charon-systemd >/dev/null 2>&1
    else
        return 2
    fi
}

WaitForCharonStop()
{
    if [ "${DRY_RUN}" = "1" ]; then
        LogInfo 'Would verify that charon stopped.'
        return 0
    else
        :
    fi

    iAttempt=0
    while [ "${iAttempt}" -lt 20 ]
    do
        iProcessState=0
        IsCharonRunning || iProcessState=$?

        case "${iProcessState}" in
            0)
                sleep 1
                ;;
            1)
                LogInfo 'charon is stopped.'
                return 0
                ;;
            2)
                LogInfo 'pgrep/pidof not found; the service stop result was accepted.'
                return 0
                ;;
            *)
                LogError 'Unexpected process-check result.'
                exit 1
                ;;
        esac

        iAttempt=$((iAttempt + 1))
    done

    LogError 'charon is still running after the service stop request.'
    exit 1
}

PrintUsage()
{
    printf 'Usage: %s [--dry-run] [--disable]\n' "$0"
    printf '\nOptions:\n'
    printf '  --dry-run  Print actions without stopping the service\n'
    printf '  --disable  Stop now and disable automatic startup\n'
    printf '\nEnvironment override:\n'
    printf '  SERVICE_NAME  Custom systemd unit name or absolute init-script path\n'
}

ParseArguments()
{
    while [ "$#" -gt 0 ]
    do
        case "$1" in
            --dry-run)
                DRY_RUN=1
                ;;
            --disable)
                DISABLE_ON_BOOT=1
                ;;
            -h|--help)
                PrintUsage
                exit 0
                ;;
            *)
                LogError "Unknown argument: $1"
                PrintUsage >&2
                exit 2
                ;;
        esac
        shift
    done
}

Main()
{
    ParseArguments "$@"
    RequireRoot
    StopCharon
    WaitForCharonStop

    if [ "${DISABLE_ON_BOOT}" = "1" ]; then
        LogInfo 'strongSwan is stopped and automatic startup is disabled.'
    else
        LogInfo 'strongSwan is stopped; its automatic-start setting was preserved.'
    fi
}

Main "$@"
