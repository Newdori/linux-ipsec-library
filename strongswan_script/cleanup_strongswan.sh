#!/bin/sh

set -eu

STRONGSWAN_CONF=${STRONGSWAN_CONF:-/etc/strongswan.conf}
STRONGSWAN_D_DIR=${STRONGSWAN_D_DIR:-/etc/strongswan.d}
SWANCTL_DIR=${SWANCTL_DIR:-/etc/swanctl}
IPSEC_CONF=${IPSEC_CONF:-/etc/ipsec.conf}
IPSEC_SECRETS=${IPSEC_SECRETS:-/etc/ipsec.secrets}
VICI_SOCKET=${VICI_SOCKET:-/run/charon.vici}
SERVICE_NAME=${SERVICE_NAME:-}
DRY_RUN=${DRY_RUN:-0}
CONFIRMED=0

MANAGED_BEGIN='# BEGIN libipsec managed plugins'
MANAGED_END='# END libipsec managed plugins'

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

RequireCommands()
{
    for pcCommandName in awk cat cp grep id kill mv readlink rm sleep
    do
        if command -v "${pcCommandName}" >/dev/null 2>&1; then
            :
        else
            LogError "Required command was not found: ${pcCommandName}"
            exit 1
        fi
    done
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

RequireConfirmation()
{
    if [ "${DRY_RUN}" = "1" ]; then
        return 0
    elif [ "${CONFIRMED}" = "1" ]; then
        return 0
    else
        LogError 'This operation permanently deletes strongSwan connections and credentials.'
        LogError 'Run with --confirm after reviewing --dry-run output.'
        exit 2
    fi
}

ValidateAbsolutePath()
{
    pcTargetPath=$1

    case "${pcTargetPath}" in
        /*)
            ;;
        *)
            LogError "Cleanup target is not an absolute path: ${pcTargetPath}"
            exit 1
            ;;
    esac
}

ValidatePurgeDirectory()
{
    pcTargetDirectory=$1
    ValidateAbsolutePath "${pcTargetDirectory}"

    case "${pcTargetDirectory}" in
        *//*|*/../*|*/..|*/./*|*/.)
            LogError "Refusing non-normalized cleanup directory: ${pcTargetDirectory}"
            exit 1
            ;;
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/proc|/root|/run|/sbin|/sys|/tmp|/usr|/var)
            LogError "Refusing unsafe cleanup directory: ${pcTargetDirectory}"
            exit 1
            ;;
        *)
            ;;
    esac

    if [ -L "${pcTargetDirectory}" ]; then
        LogError "Refusing a symbolic-link cleanup directory: ${pcTargetDirectory}"
        exit 1
    else
        :
    fi

    pcResolvedDirectory=$(readlink -f "${pcTargetDirectory}")
    case "${pcResolvedDirectory}" in
        */swanctl)
            printf '%s\n' "${pcResolvedDirectory}"
            ;;
        *)
            LogError "Cleanup directory must resolve to a directory named swanctl: ${pcResolvedDirectory}"
            exit 1
            ;;
    esac
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

StopAndDisableService()
{
    pcDetectedService=$(DetectServiceName || true)

    if [ -z "${pcDetectedService}" ]; then
        LogInfo 'No strongSwan service definition was found; checking direct charon processes.'
        return 0
    else
        :
    fi

    case "${pcDetectedService}" in
        /*)
            RunCommand "${pcDetectedService}" stop
            DisableSysvService "${pcDetectedService}"
            ;;
        *)
            RunCommand systemctl stop "${pcDetectedService}.service"
            RunCommand systemctl disable "${pcDetectedService}.service"
            ;;
    esac

    LogInfo "Stopped and disabled strongSwan using: ${pcDetectedService}"
}

TerminateDirectCharon()
{
    if command -v pgrep >/dev/null 2>&1; then
        for pcProcessName in charon charon-systemd
        do
            for iProcessId in $(pgrep -x "${pcProcessName}" 2>/dev/null || true)
            do
                RunCommand kill -TERM "${iProcessId}"
            done
        done
    elif command -v pidof >/dev/null 2>&1; then
        for pcProcessName in charon charon-systemd
        do
            for iProcessId in $(pidof "${pcProcessName}" 2>/dev/null || true)
            do
                RunCommand kill -TERM "${iProcessId}"
            done
        done
    else
        LogInfo 'pgrep/pidof not found; the service stop result was accepted.'
    fi
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
                LogInfo 'Process inspection is unavailable; continuing after service stop.'
                return 0
                ;;
            *)
                LogError 'Unexpected process-check result.'
                exit 1
                ;;
        esac

        iAttempt=$((iAttempt + 1))
    done

    LogError 'charon is still running; credential deletion was aborted.'
    exit 1
}

RestoreOrRemoveManagedConfiguration()
{
    pcManagedConfiguration="${STRONGSWAN_D_DIR}/charon/90-libipsec-native.conf"
    pcManagedBackup="${pcManagedConfiguration}.libipsec-native.bak"
    ValidateAbsolutePath "${pcManagedConfiguration}"

    if [ -f "${pcManagedBackup}" ]; then
        RunCommand cp -p "${pcManagedBackup}" "${pcManagedConfiguration}"
        RunCommand rm -f "${pcManagedBackup}"
        LogInfo "Restored original plugin configuration: ${pcManagedConfiguration}"
    elif [ -e "${pcManagedConfiguration}" ] || [ -L "${pcManagedConfiguration}" ]; then
        RunCommand rm -f "${pcManagedConfiguration}"
        LogInfo "Removed managed plugin configuration: ${pcManagedConfiguration}"
    else
        LogInfo "Managed plugin configuration is already absent: ${pcManagedConfiguration}"
    fi
}

RestoreOrCleanMainConfiguration()
{
    pcMainBackup="${STRONGSWAN_CONF}.libipsec-native.bak"
    ValidateAbsolutePath "${STRONGSWAN_CONF}"

    if [ -f "${pcMainBackup}" ]; then
        RunCommand cp -p "${pcMainBackup}" "${STRONGSWAN_CONF}"
        RunCommand rm -f "${pcMainBackup}"
        LogInfo "Restored original main configuration: ${STRONGSWAN_CONF}"
    elif [ -f "${STRONGSWAN_CONF}" ] && \
        grep -Fq "${MANAGED_BEGIN}" "${STRONGSWAN_CONF}"
    then
        if [ "${DRY_RUN}" = "1" ]; then
            LogInfo "Would remove the managed block from: ${STRONGSWAN_CONF}"
        else
            pcTemporaryConfiguration="${STRONGSWAN_CONF}.cleanup.$$"
            trap 'rm -f "${pcTemporaryConfiguration:-}"' EXIT HUP INT TERM
            awk -v pcBegin="${MANAGED_BEGIN}" -v pcEnd="${MANAGED_END}" '
                $0 == pcBegin { bSkip = 1; next }
                $0 == pcEnd { bSkip = 0; next }
                bSkip != 1 { print }
            ' "${STRONGSWAN_CONF}" > "${pcTemporaryConfiguration}"
            cp -p "${STRONGSWAN_CONF}" "${pcTemporaryConfiguration}.mode"
            cat "${pcTemporaryConfiguration}" > "${pcTemporaryConfiguration}.mode"
            mv "${pcTemporaryConfiguration}.mode" "${STRONGSWAN_CONF}"
            rm -f "${pcTemporaryConfiguration}"
            trap - EXIT HUP INT TERM
            LogInfo "Removed managed block from: ${STRONGSWAN_CONF}"
        fi
    else
        LogInfo 'No managed block was found in the main configuration.'
    fi
}

PurgeDirectoryContents()
{
    pcTargetDirectory=$1

    if [ ! -d "${pcTargetDirectory}" ]; then
        LogInfo "Configuration directory is already absent: ${pcTargetDirectory}"
        return 0
    else
        :
    fi

    pcTargetDirectory=$(ValidatePurgeDirectory "${pcTargetDirectory}")

    for pcTargetPath in \
        "${pcTargetDirectory}"/* \
        "${pcTargetDirectory}"/.[!.]* \
        "${pcTargetDirectory}"/..?*
    do
        if [ -e "${pcTargetPath}" ] || [ -L "${pcTargetPath}" ]; then
            RunCommand rm -rf "${pcTargetPath}"
        else
            :
        fi
    done

    LogInfo "Removed persistent connections and credentials from: ${pcTargetDirectory}"
}

RemoveConfigurationFile()
{
    pcTargetPath=$1
    ValidateAbsolutePath "${pcTargetPath}"

    if [ -e "${pcTargetPath}" ] || [ -L "${pcTargetPath}" ]; then
        RunCommand rm -f "${pcTargetPath}"
        LogInfo "Removed configuration file: ${pcTargetPath}"
    else
        LogInfo "Configuration file is already absent: ${pcTargetPath}"
    fi
}

RemoveViciSocket()
{
    ValidateAbsolutePath "${VICI_SOCKET}"

    if [ -e "${VICI_SOCKET}" ] || [ -L "${VICI_SOCKET}" ]; then
        RunCommand rm -f "${VICI_SOCKET}"
        LogInfo "Removed VICI runtime socket: ${VICI_SOCKET}"
    else
        LogInfo "VICI runtime socket is already absent: ${VICI_SOCKET}"
    fi
}

PrintUsage()
{
    printf 'Usage: %s --dry-run | --confirm\n' "$0"
    printf '\nOptions:\n'
    printf '  --dry-run  Show destructive actions without changing the device\n'
    printf '  --confirm  Permanently reset strongSwan operational configuration\n'
    printf '\nThe strongSwan package and plugin binaries are not removed.\n'
}

ParseArguments()
{
    while [ "$#" -gt 0 ]
    do
        case "$1" in
            --dry-run)
                DRY_RUN=1
                ;;
            --confirm)
                CONFIRMED=1
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
    RequireCommands
    RequireRoot
    RequireConfirmation

    StopAndDisableService
    TerminateDirectCharon
    WaitForCharonStop
    RestoreOrRemoveManagedConfiguration
    RestoreOrCleanMainConfiguration
    PurgeDirectoryContents "${SWANCTL_DIR}"
    RemoveConfigurationFile "${IPSEC_CONF}"
    RemoveConfigurationFile "${IPSEC_SECRETS}"
    RemoveViciSocket

    LogInfo 'strongSwan operational state has been reset.'
    LogInfo 'Run initialize_strongswan.sh to configure and start it again.'
}

Main "$@"
