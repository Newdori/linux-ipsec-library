#!/bin/sh

set -eu

STRONGSWAN_CONF=${STRONGSWAN_CONF:-/etc/strongswan.conf}
STRONGSWAN_D_DIR=${STRONGSWAN_D_DIR:-/etc/strongswan.d}
IPSEC_CONF=${IPSEC_CONF:-/etc/ipsec.conf}
IPSEC_SECRETS=${IPSEC_SECRETS:-/etc/ipsec.secrets}
VICI_SOCKET=${VICI_SOCKET:-/run/charon.vici}
SERVICE_NAME=${SERVICE_NAME:-}
DRY_RUN=${DRY_RUN:-0}
REQUIRE_PLUGIN_FILES=${REQUIRE_PLUGIN_FILES:-1}
DATAPATH_BACKEND=${DATAPATH_BACKEND:-kernel-xfrm}
KERNEL_LIBIPSEC_RAW_ESP=${KERNEL_LIBIPSEC_RAW_ESP:-0}
KERNEL_LIBIPSEC_ALLOW_PEER_TS=${KERNEL_LIBIPSEC_ALLOW_PEER_TS:-1}
ADJUST_RP_FILTER=${ADJUST_RP_FILTER:-0}
STRONGSWAN_PLUGIN_DIRS=${STRONGSWAN_PLUGIN_DIRS:-/usr/lib/ipsec/plugins:/usr/lib64/ipsec/plugins:/usr/lib/strongswan/plugins:/usr/lib64/strongswan/plugins:/lib/ipsec/plugins:/lib64/ipsec/plugins:/usr/local/lib/ipsec/plugins}

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

RequireCommands()
{
    for pcCommandName in awk grep id cp mkdir chmod mv rm sleep
    do
        if command -v "${pcCommandName}" >/dev/null 2>&1; then
            :
        else
            LogError "Required command was not found: ${pcCommandName}"
            exit 1
        fi
    done
}

FindPluginFile()
{
    pcPluginName=$1
    pcPreviousIfs=$IFS
    IFS=:

    for pcPluginDirectory in ${STRONGSWAN_PLUGIN_DIRS}
    do
        if [ -f "${pcPluginDirectory}/libstrongswan-${pcPluginName}.so" ]; then
            IFS=$pcPreviousIfs
            printf '%s\n' "${pcPluginDirectory}/libstrongswan-${pcPluginName}.so"
            return 0
        else
            :
        fi
    done

    IFS=$pcPreviousIfs
    return 1
}

CheckPluginFiles()
{
    pcViciPlugin=$(FindPluginFile vici || true)
    pcKernelNetlinkPlugin=$(FindPluginFile kernel-netlink || true)
    pcKernelLibipsecPlugin=$(FindPluginFile kernel-libipsec || true)

    if [ -z "${pcViciPlugin}" ]; then
        if [ "${REQUIRE_PLUGIN_FILES}" = "1" ]; then
            LogError 'The installed strongSwan build does not contain the vici plugin file.'
            LogError 'For a monolithic strongSwan build, set REQUIRE_PLUGIN_FILES=0.'
            exit 1
        else
            LogInfo 'VICI plugin file not found; accepting a monolithic strongSwan build.'
        fi
    else
        LogInfo "Found VICI plugin: ${pcViciPlugin}"
    fi

    if [ -z "${pcKernelNetlinkPlugin}" ]; then
        if [ "${REQUIRE_PLUGIN_FILES}" = "1" ]; then
            LogError 'The installed strongSwan build does not contain the kernel-netlink plugin file.'
            LogError 'For a monolithic strongSwan build, set REQUIRE_PLUGIN_FILES=0.'
            exit 1
        else
            LogInfo 'kernel-netlink plugin file not found; accepting a monolithic strongSwan build.'
        fi
    else
        LogInfo "Found kernel-netlink plugin: ${pcKernelNetlinkPlugin}"
    fi

    if [ "${DATAPATH_BACKEND}" = "kernel-libipsec" ]; then
        if [ -z "${pcKernelLibipsecPlugin}" ]; then
            if [ "${REQUIRE_PLUGIN_FILES}" = "1" ]; then
                LogError 'The installed strongSwan build does not contain the kernel-libipsec plugin file.'
                exit 1
            else
                LogInfo 'kernel-libipsec plugin file not found; accepting a monolithic strongSwan build.'
            fi
        else
            LogInfo "Found kernel-libipsec plugin: ${pcKernelLibipsecPlugin}"
        fi
    else
        :
    fi
}

WriteKernelLibipsecSettings()
{
    printf '\n'
    printf 'socket-default {\n'
    printf '    load = yes\n'
    printf '    fwmark = 0x42\n'
    printf '}\n'
    printf '\n'
    printf 'kernel-libipsec {\n'
    printf '    load = yes\n'
    printf '    allow_peer_ts = %s\n' \
        "$([ "${KERNEL_LIBIPSEC_ALLOW_PEER_TS}" = "1" ] && printf yes || printf no)"
    printf '    raw_esp = %s\n' \
        "$([ "${KERNEL_LIBIPSEC_RAW_ESP}" = "1" ] && printf yes || printf no)"
    printf '}\n'
}

CreateBackup()
{
    pcTargetPath=$1

    if [ ! -f "${pcTargetPath}" ]; then
        return 0
    else
        :
    fi

    pcBackupPath="${pcTargetPath}.libipsec-native.bak"
    if [ -e "${pcBackupPath}" ]; then
        :
    elif [ "${DRY_RUN}" = "1" ]; then
        LogInfo "Would create backup: ${pcBackupPath}"
    else
        RunCommand cp -p "${pcTargetPath}" "${pcBackupPath}"
        LogInfo "Created backup: ${pcBackupPath}"
    fi
}

WriteModularConfiguration()
{
    pcCharonDirectory="${STRONGSWAN_D_DIR}/charon"
    pcManagedConfiguration="${pcCharonDirectory}/90-libipsec-native.conf"

    RunCommand mkdir -p "${pcCharonDirectory}"
    CreateBackup "${pcManagedConfiguration}"

    if [ "${DRY_RUN}" = "1" ]; then
        LogInfo "Would write: ${pcManagedConfiguration}"
        return 0
    else
        :
    fi

    pcTemporaryConfiguration="${pcManagedConfiguration}.tmp.$$"
    trap 'rm -f "${pcTemporaryConfiguration:-}"' EXIT HUP INT TERM

    {
        printf 'vici {\n'
        printf '    load = yes\n'
        printf '    socket = unix://%s\n' "${VICI_SOCKET}"
        printf '}\n'
        printf '\n'
        printf 'kernel-netlink {\n'
        printf '    load = yes\n'
        if [ "${DATAPATH_BACKEND}" = "kernel-libipsec" ] && \
            [ "${KERNEL_LIBIPSEC_ALLOW_PEER_TS}" = "1" ]; then
            printf '    fwmark = !0x42\n'
        else
            :
        fi
        printf '}\n'
        if [ "${DATAPATH_BACKEND}" = "kernel-libipsec" ]; then
            WriteKernelLibipsecSettings
        else
            printf '\n'
            printf 'kernel-libipsec {\n'
            printf '    load = no\n'
            printf '}\n'
        fi
    } > "${pcTemporaryConfiguration}"

    chmod 0644 "${pcTemporaryConfiguration}"
    mv "${pcTemporaryConfiguration}" "${pcManagedConfiguration}"
    trap - EXIT HUP INT TERM
}

WriteMainConfiguration()
{
    if [ ! -f "${STRONGSWAN_CONF}" ]; then
        LogError "strongSwan configuration was not found: ${STRONGSWAN_CONF}"
        exit 1
    else
        :
    fi

    CreateBackup "${STRONGSWAN_CONF}"

    if [ "${DRY_RUN}" = "1" ]; then
        LogInfo "Would replace the managed plugin block in: ${STRONGSWAN_CONF}"
        return 0
    else
        :
    fi

    pcTemporaryConfiguration="${STRONGSWAN_CONF}.tmp.$$"
    trap 'rm -f "${pcTemporaryConfiguration:-}"' EXIT HUP INT TERM
    awk -v pcManagedBegin="${MANAGED_BEGIN}" \
        -v pcManagedEnd="${MANAGED_END}" '
        $0 == pcManagedBegin { bSkip = 1; next }
        $0 == pcManagedEnd { bSkip = 0; next }
        !bSkip { print }
    ' "${STRONGSWAN_CONF}" > "${pcTemporaryConfiguration}"

    {
        printf '\n%s\n' "${MANAGED_BEGIN}"
        printf 'charon {\n'
        printf '    plugins {\n'
        printf '        vici {\n'
        printf '            load = yes\n'
        printf '            socket = unix://%s\n' "${VICI_SOCKET}"
        printf '        }\n'
        printf '        kernel-netlink {\n'
        printf '            load = yes\n'
        if [ "${DATAPATH_BACKEND}" = "kernel-libipsec" ] && \
            [ "${KERNEL_LIBIPSEC_ALLOW_PEER_TS}" = "1" ]; then
            printf '            fwmark = !0x42\n'
        else
            :
        fi
        printf '        }\n'
        if [ "${DATAPATH_BACKEND}" = "kernel-libipsec" ]; then
            printf '        socket-default {\n'
            printf '            load = yes\n'
            printf '            fwmark = 0x42\n'
            printf '        }\n'
            printf '        kernel-libipsec {\n'
            printf '            load = yes\n'
            printf '            allow_peer_ts = %s\n' \
                "$([ "${KERNEL_LIBIPSEC_ALLOW_PEER_TS}" = "1" ] && printf yes || printf no)"
            printf '            raw_esp = %s\n' \
                "$([ "${KERNEL_LIBIPSEC_RAW_ESP}" = "1" ] && printf yes || printf no)"
            printf '        }\n'
        else
            printf '        kernel-libipsec {\n'
            printf '            load = no\n'
            printf '        }\n'
        fi
        printf '    }\n'
        printf '}\n'
        printf '%s\n' "${MANAGED_END}"
    } >> "${pcTemporaryConfiguration}"

    chmod 0644 "${pcTemporaryConfiguration}"
    mv "${pcTemporaryConfiguration}" "${STRONGSWAN_CONF}"
    trap - EXIT HUP INT TERM
}

AdjustKernelLibipsecHostSettings()
{
    if [ "${DATAPATH_BACKEND}" != "kernel-libipsec" ] || \
        [ "${ADJUST_RP_FILTER}" != "1" ]; then
        return 0
    else
        :
    fi
    if command -v sysctl >/dev/null 2>&1; then
        RunCommand sysctl -w net.ipv4.conf.all.rp_filter=2
    else
        LogError 'sysctl is required when ADJUST_RP_FILTER=1.'
        exit 1
    fi
}

ValidateDatapathOptions()
{
    case "${DATAPATH_BACKEND}" in
        kernel-xfrm|kernel-libipsec)
            ;;
        *)
            LogError "Unsupported datapath backend: ${DATAPATH_BACKEND}"
            exit 2
            ;;
    esac
    for pcBooleanValue in \
        "${KERNEL_LIBIPSEC_RAW_ESP}" \
        "${KERNEL_LIBIPSEC_ALLOW_PEER_TS}" \
        "${ADJUST_RP_FILTER}"
    do
        case "${pcBooleanValue}" in
            0|1)
                ;;
            *)
                LogError 'Boolean datapath options must be 0 or 1.'
                exit 2
                ;;
        esac
    done
}

ConfigurePlugins()
{
    if [ -f "${STRONGSWAN_CONF}" ] && \
        grep -Eq 'include[[:space:]]+.*strongswan\.d/charon/.*\.conf' \
        "${STRONGSWAN_CONF}"
    then
        WriteModularConfiguration
    elif [ -d "${STRONGSWAN_D_DIR}/charon" ] && \
        { [ -f "${STRONGSWAN_D_DIR}/charon/vici.conf" ] || \
          [ -f "${STRONGSWAN_D_DIR}/charon/kernel-netlink.conf" ]; }
    then
        WriteModularConfiguration
    else
        WriteMainConfiguration
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

EnsureLegacyConfiguration()
{
    pcDetectedService=$1

    case "${pcDetectedService}" in
        strongswan-starter|ipsec|/*)
            ;;
        *)
            return 0
            ;;
    esac

    if [ ! -f "${IPSEC_CONF}" ]; then
        if [ "${DRY_RUN}" = "1" ]; then
            LogInfo "Would create minimal legacy configuration: ${IPSEC_CONF}"
        else
            pcTemporaryIpsecConfiguration="${IPSEC_CONF}.tmp.$$"
            trap 'rm -f "${pcTemporaryIpsecConfiguration:-}"' EXIT HUP INT TERM
            {
                printf 'config setup\n'
                printf '    uniqueids=no\n'
            } > "${pcTemporaryIpsecConfiguration}"
            chmod 0644 "${pcTemporaryIpsecConfiguration}"
            mv "${pcTemporaryIpsecConfiguration}" "${IPSEC_CONF}"
            trap - EXIT HUP INT TERM
            LogInfo "Created minimal legacy configuration: ${IPSEC_CONF}"
        fi
    else
        :
    fi

    if [ ! -f "${IPSEC_SECRETS}" ]; then
        if [ "${DRY_RUN}" = "1" ]; then
            LogInfo "Would create empty legacy credential file: ${IPSEC_SECRETS}"
        else
            pcTemporaryIpsecSecrets="${IPSEC_SECRETS}.tmp.$$"
            trap 'rm -f "${pcTemporaryIpsecSecrets:-}"' EXIT HUP INT TERM
            : > "${pcTemporaryIpsecSecrets}"
            chmod 0600 "${pcTemporaryIpsecSecrets}"
            mv "${pcTemporaryIpsecSecrets}" "${IPSEC_SECRETS}"
            trap - EXIT HUP INT TERM
            LogInfo "Created empty legacy credential file: ${IPSEC_SECRETS}"
        fi
    else
        :
    fi
}

StartCharon()
{
    pcDetectedService=$(DetectServiceName || true)

    if [ -z "${pcDetectedService}" ]; then
        LogError 'No supported strongSwan systemd unit or SysV init script was found.'
        LogError 'Set SERVICE_NAME to the systemd unit name if the image uses a custom unit.'
        exit 1
    else
        :
    fi

    EnsureLegacyConfiguration "${pcDetectedService}"

    case "${pcDetectedService}" in
        /*)
            RunCommand "${pcDetectedService}" restart
            ;;
        *)
            RunCommand systemctl enable "${pcDetectedService}.service"
            RunCommand systemctl restart "${pcDetectedService}.service"
            ;;
    esac

    LogInfo "Restarted strongSwan using: ${pcDetectedService}"
}

WaitForViciSocket()
{
    if [ "${DRY_RUN}" = "1" ]; then
        LogInfo "Would wait for VICI socket: ${VICI_SOCKET}"
        return 0
    else
        :
    fi

    iAttempt=0
    while [ "${iAttempt}" -lt 50 ]
    do
        if [ -S "${VICI_SOCKET}" ]; then
            LogInfo "VICI socket is ready: ${VICI_SOCKET}"
            return 0
        else
            sleep 1
            iAttempt=$((iAttempt + 1))
        fi
    done

    LogError "VICI socket did not appear: ${VICI_SOCKET}"
    LogError 'Check the charon log and confirm that the vici plugin loaded.'
    exit 1
}

WaitForDatapath()
{
    if [ "${DATAPATH_BACKEND}" != "kernel-libipsec" ]; then
        LogInfo 'Kernel XFRM datapath selected.'
        return 0
    else
        :
    fi
    if [ "${DRY_RUN}" = "1" ]; then
        LogInfo 'Would wait for the kernel-libipsec TUN device: ipsec0'
        return 0
    else
        :
    fi

    iAttempt=0
    while [ "${iAttempt}" -lt 20 ]
    do
        if [ -d /sys/class/net/ipsec0 ]; then
            LogInfo 'kernel-libipsec TUN device is ready: ipsec0'
            return 0
        else
            sleep 1
            iAttempt=$((iAttempt + 1))
        fi
    done

    LogError 'kernel-libipsec was requested, but ipsec0 was not created.'
    LogError 'Check the charon service log and kernel-libipsec plugin dependencies.'
    exit 1
}

CheckCharonProcess()
{
    if [ "${DRY_RUN}" = "1" ]; then
        LogInfo 'Would verify the charon process.'
    elif command -v pgrep >/dev/null 2>&1 && \
        { pgrep -x charon >/dev/null 2>&1 || \
          pgrep -x charon-systemd >/dev/null 2>&1; }
    then
        LogInfo 'charon is running.'
    elif command -v pidof >/dev/null 2>&1 && \
        { pidof charon >/dev/null 2>&1 || \
          pidof charon-systemd >/dev/null 2>&1; }
    then
        LogInfo 'charon is running.'
    elif ! command -v pgrep >/dev/null 2>&1 && \
        ! command -v pidof >/dev/null 2>&1
    then
        LogInfo 'pgrep/pidof not found; VICI socket readiness will verify startup.'
    else
        LogError 'The strongSwan service started, but no charon process was found.'
        exit 1
    fi
}

PrintUsage()
{
    printf 'Usage: %s [--dry-run] [--datapath kernel-xfrm|kernel-libipsec]\n' "$0"
    printf '          [--raw-esp] [--no-allow-peer-ts] [--adjust-rp-filter]\n'
    printf '\nEnvironment overrides:\n'
    printf '  STRONGSWAN_CONF  Main configuration path\n'
    printf '  STRONGSWAN_D_DIR Modular configuration directory\n'
    printf '  VICI_SOCKET      VICI Unix socket path\n'
    printf '  SERVICE_NAME     Custom systemd unit name\n'
    printf '  STRONGSWAN_PLUGIN_DIRS  Colon-separated plugin directories\n'
    printf '  REQUIRE_PLUGIN_FILES   Set to 0 for a monolithic build\n'
    printf '  DATAPATH_BACKEND       kernel-xfrm or kernel-libipsec\n'
}

ParseArguments()
{
    while [ "$#" -gt 0 ]
    do
        case "$1" in
            --dry-run)
                DRY_RUN=1
                ;;
            --datapath)
                if [ "$#" -lt 2 ]; then
                    LogError '--datapath requires a backend name.'
                    exit 2
                else
                    DATAPATH_BACKEND=$2
                    shift
                fi
                ;;
            --raw-esp)
                KERNEL_LIBIPSEC_RAW_ESP=1
                ;;
            --no-allow-peer-ts)
                KERNEL_LIBIPSEC_ALLOW_PEER_TS=0
                ;;
            --adjust-rp-filter)
                ADJUST_RP_FILTER=1
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
    ValidateDatapathOptions
    RequireCommands
    RequireRoot
    CheckPluginFiles
    ConfigurePlugins
    AdjustKernelLibipsecHostSettings
    StartCharon
    CheckCharonProcess
    WaitForViciSocket
    WaitForDatapath
    LogInfo "strongSwan initialization completed: datapath=${DATAPATH_BACKEND}"
}

Main "$@"
