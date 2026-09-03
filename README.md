# Linux IPsec Control Library

`libipsecctrl` is a C11 control/status library for strongSwan and Linux IPsec.
It talks to an already-running `charon` process through the VICI Unix-domain
protocol and reads Linux networking state through Netlink and `/proc`. It does
not run `swanctl`, `ip`, shell commands, or service-management commands, and it
does not link strongSwan GPL libraries.

The project currently provides:

- VICI connection, PSK credential, IKE SA, and CHILD SA control;
- IKE/CHILD/connection/algorithm/daemon status as C structures;
- Linux XFRM state, policy, and statistics queries;
- interface, address, and route queries through `NETLINK_ROUTE`;
- XFRM and strongSwan kernel-libipsec datapath detection;
- independent protected-packet and plain-packet delivery paths;
- static and shared libraries named `libipsecctrl.a` and `libipsecctrl.so`;
- an interactive diagnostic application named `ipsec_app`.

The library does not implement IKEv2 or ESP cryptography. IKEv2 remains in
`charon`; ESP processing remains in the selected XFRM or kernel-libipsec
backend.

## Architecture

```text
Application
    |
    +-- Control API ---------------- VICI ---------------- charon
    |
    +-- Protected packet I/O layer
    |
    +-- Plain packet delivery layer
    |
libipsecctrl
    |
    +-- XFRM backend ---------------- Linux XFRM
    |
    +-- kernel-libipsec backend ----- charon/libipsec + charon TUN
```

Three choices are independent:

1. Datapath backend: `XFRM` or `kernel-libipsec`.
2. Protected packet path: `SYSTEM` or `APPLICATION`.
3. Plain packet path: `SYSTEM` or `APPLICATION`.

The backend answers **who performs ESP authentication, anti-replay,
encryption/decryption, and encapsulation**. A packet path answers **where the
processed packet is delivered**. `SYSTEM` does not mean that the kernel performs
ESP. For example, kernel-libipsec performs ESP in strongSwan user space while a
`SYSTEM` path still uses the normal Linux network path.

### Packet-path combinations

| Protected | Plain | Transmit behavior | Receive behavior |
|---|---|---|---|
| SYSTEM | SYSTEM | ESP continues to normal network egress | Plain inner packet continues to Linux stack |
| APPLICATION | SYSTEM | Application receives completed outer IPv4/ESP packet | Plain inner packet continues to Linux stack |
| SYSTEM | APPLICATION | ESP continues to normal network egress | Application receives the decrypted inner IPv4 packet |
| APPLICATION | APPLICATION | Application receives completed ESP packet | Application submits ESP and receives the decrypted inner IPv4 packet |

All four choices are accepted with either backend, for eight configuration
combinations. `SYSTEM/SYSTEM` is the default and retains ordinary Linux IPsec
behavior.

An `APPLICATION` path does not move ESP cryptography into the calling program.
Application-specific processing between receive and submit calls is outside this
library.

## Public packet APIs

```c
IpsecError_t ReceiveIpsecProtectedPacket(
    IpsecContext_t *pContext,
    IpsecProtectedPacket_t *pPacket,
    uint32_t uiTimeoutMs);

IpsecError_t SubmitIpsecProtectedPacket(
    IpsecContext_t *pContext,
    const IpsecProtectedPacket_t *pPacket);

IpsecError_t ReceiveIpsecPlainPacket(
    IpsecContext_t *pContext,
    IpsecPlainPacket_t *pPacket,
    uint32_t uiTimeoutMs);

IpsecError_t GetIpsecPacketPathStatus(
    IpsecContext_t *pContext,
    IpsecPacketPathStatus_t *pStatus);
```

`ReceiveIpsecProtectedPacket()` returns a complete outbound packet containing
the outer IPv4 header and raw ESP. `SubmitIpsecProtectedPacket()` accepts the
same complete raw ESP packet in the inbound direction. The library validates
framing and configured peer scope; the selected backend validates SPI,
authentication, anti-replay, and encryption state.

`ReceiveIpsecPlainPacket()` returns the **entire authenticated, decrypted, and
decapsulated inner IPv4 packet**, not only its TCP/UDP/ICMP payload:

```text
Inner IPv4 header | transport header | application payload
```

The caller owns each packet buffer. No packet API allocates a per-packet output
buffer. The current protected implementation requires a 65,535-byte buffer to
ensure a TUN read is never silently truncated. The plain API reports
`IPSEC_ERR_BUFFER_TOO_SMALL` if the caller-provided capacity is insufficient.
IPv6 plain delivery and protected UDP encapsulation are not implemented and
return explicit errors.

Calling a packet API while its corresponding path is `SYSTEM` returns
`IPSEC_ERR_PACKET_PATH_MISMATCH`.

## Protected APPLICATION implementation

The implementation reuses the existing scoped TC/TUN mechanism:

1. the application supplies a dedicated physical egress interface;
2. each loaded connection supplies one literal local/remote outer IPv4 pair;
3. the OS supplies an empty `clsact` qdisc;
4. the library creates a non-persistent protected-path TUN;
5. connection-scoped TC filters redirect matching raw ESP from physical egress to that
   TUN with stolen semantics, so the packet is not cloned to the NIC;
6. the receive API reads the complete packet from the TUN;
7. the submit API validates and writes the inbound packet to the protected TUN.

The library owns only its TUN and reserved filters. It does not add routes,
addresses, firewall rules, or qdiscs. The configured TC priority pair and the
library handle namespace must be reserved for the context. Connection load
installs a peer filter pair, connection unload removes it, and failed loads are
rolled back. Stop traffic and terminate affected SAs before context destruction;
cleanup retries removal of every registered peer filter.

This first implementation is IPv4 raw ESP only. NAT-T/UDP-encapsulated ESP,
fragmented outer IPv4 and hardware-offloaded XFRM SAs are rejected. One context
supports up to 256 connection-scoped peers. kernel-libipsec protected delivery
requires strongSwan 5.9.11 or newer with the plugin's raw-ESP support enabled.
These requirements do not apply to a `SYSTEM` protected path.

## Plain APPLICATION implementation

Plain delivery uses raw `NETLINK_NETFILTER`/NFQUEUE without linking a GPL
netfilter client library. The application selects a nonzero queue number. An
OS administrator must provision one exact post-decrypt rule before library
initialization:

- XFRM backend: select only inbound packets carrying the matching inbound IPsec
  policy and enqueue them after successful XFRM decapsulation.
- kernel-libipsec backend: select only packets entering from the discovered or
  configured charon-owned TUN and enqueue them.

Do not configure a queue-bypass/accept fallback for this path. The library
copies a validated complete IPv4 packet and then sends an `NF_DROP` verdict.
Consequently a successfully returned packet belongs to the application and is
not also delivered through the Linux stack. Malformed, truncated, wrong-TUN,
IPv6, and undersized-buffer cases are rejected; queued packets with a usable ID
are dropped even when parsing fails.

The library deliberately does not create firewall rules. Queue binding proves
that the local queue endpoint is ready; it cannot prove that an administrator's
rule selects only authenticated post-decrypt traffic. The rule and network
namespace are therefore part of the trusted deployment boundary. For XFRM,
policy selection must be verified in the actual kernel. For kernel-libipsec,
the library also checks the NFQUEUE ingress ifindex against the selected charon
TUN.

Relevant implementation background is documented by the
[strongSwan kernel-libipsec plugin](https://docs.strongswan.org/docs/latest/plugins/kernelLibipsec.html),
[strongSwan traffic dump guidance](https://docs.strongswan.org/docs/latest/howtos/trafficDumps.html),
and the [Linux NFQUEUE Netlink specification](https://docs.kernel.org/netlink/specs/nfnetlink_queue.html).

Plain APPLICATION requires continuous queue draining. Treat an application
exit, queue overflow, or missing queue consumer as fail-closed packet loss and
monitor it operationally.

The diagnostic application records the expected rule hook as
`plain_netfilter_hook=input|forward`. Use `input` when the decrypted inner
destination is local to the host and `forward` when Linux would route it
through the host. This setting documents and validates deployment intent; it
does not create, replace, or delete an OS Netfilter rule.

## Datapath configuration

```c
IpsecDatapathConfig_t Datapath = {
    .uiStructSize = sizeof(Datapath),
    .ePreference = IPSEC_DATAPATH_PREFER_XFRM,
    .eProtectedPacketPath = IPSEC_PACKET_PATH_SYSTEM,
    .ePlainPacketPath = IPSEC_PACKET_PATH_SYSTEM
};
```

`IPSEC_DATAPATH_PREFER_AUTO` probes kernel-libipsec first and then XFRM only
when the former is absent. An ambiguous or inconsistent kernel-libipsec setup
is an error, not a silent backend change. The library never changes the backend
loaded inside `charon`.

For kernel-libipsec, an empty `acKernelLibipsecTunName` preserves automatic TUN
discovery. A nonempty value selects an existing interface and validates its
existence, TUN kind, UP state, route coverage, and backend consistency. The
library never creates or renames charon's TUN and never assumes a fixed TUN
name.

Protected APPLICATION additionally uses:

```text
acProtectedInterfaceName
acProtectedEgressInterfaceName
usProtectedFilterPriority
```

Leave `acProtectedLocalAddress` and `acProtectedRemoteAddress` empty for normal
per-connection scope. Supplying both preserves the legacy single-peer fixed
scope and rejects a connection whose outer pair differs.

Plain APPLICATION additionally requires:

```text
usPlainQueueNumber
```

`GetIpsecDatapathStatusEx()` reports backend readiness, both path modes, both
path readiness states, installed CHILD count, and a local `bTrafficReady`
condition. Readiness is not proof of peer reachability or end-to-end packet
delivery. XFRM-only status APIs return backend mismatch when kernel-libipsec is
active instead of returning misleading empty data.

## Control API example

```c
IpsecContext_t *pContext = NULL;
IpsecConfig_t Config = {
    .uiStructSize = sizeof(Config),
    .pcViciSocketPath = "/run/charon.vici"
};
IpsecDatapathConfig_t Datapath = {
    .uiStructSize = sizeof(Datapath),
    .ePreference = IPSEC_DATAPATH_PREFER_XFRM,
    .eProtectedPacketPath = IPSEC_PACKET_PATH_SYSTEM,
    .ePlainPacketPath = IPSEC_PACKET_PATH_SYSTEM
};

IpsecError_t eError = InitializeIpsecWithDatapath(
    &pContext, &Config, &Datapath);
if (IPSEC_OK == eError) {
    /* Add connection/PSK, initiate IKE/CHILD, query status. */
    DeinitializeIpsec(pContext);
}
```

VICI, context, connection, credential, SA, wait, logger, ownership, and
diagnostic contracts remain in the public headers. `charon` must already be
running and expose VICI. The library never starts or stops it.

## Diagnostic application

Role-specific example files are under `app/config/`. Each file contains both
application defaults and the current algorithm policy. The optional
`management.conf` input remains a legacy override. New packet-path keys are:

```text
datapath_backend=auto
protected_packet_path=system
plain_packet_path=system
kernel_libipsec_tun=

# Protected APPLICATION only
protected_interface=ipsec-path
protected_egress_interface=eth0
protected_filter_priority=32000

# Optional legacy fixed scope; omit both for peer/connection-derived filters
# protected_local_ip=192.0.2.1
# protected_remote_ip=192.0.2.2

# Plain APPLICATION only
plain_queue_number=32002
plain_netfilter_hook=input
```

No compatibility aliases for previous packet-path names are accepted.
Packet-path settings are context-wide and require an application restart to
change.

Interactive commands include:

```text
show datapath
show packet-path
packet protected-receive FILE [--timeout-ms N]
packet protected-submit FILE
packet plain-receive FILE [--timeout-ms N]
peer listen port 39002
peer listen address 192.0.2.10 port 39002
peer listen show
peer listen stop
peer register 192.0.2.10 39002
```

Peer registration uses TCP only as a control plane. The initiator and
responder exchange their IKE/ESP outer endpoint and inner `local_ts`; the TCP
source address is not treated as the IPsec endpoint. The initiator command
without an address binds the listener to the wildcard address selected for the
configured IP family.

All ordinary connection, credential, IKE, CHILD, rekey, show, loop, and
algorithm-test commands remain available. Automated traffic-oriented algorithm
tests are intended for `SYSTEM/SYSTEM`; packet APPLICATION verification is an
explicit diagnostic workflow.

## Build

### GNU Make

From `src/`:

```sh
make            # host and aarch64/ZynqMP libraries
make host       # host only
make zynqmp     # aarch64 only; default compiler aarch64-linux-gnu-gcc
make clean
make host clean
make zynqmp clean
```

Outputs:

```text
lib/x86_64/libipsecctrl.a
lib/x86_64/libipsecctrl.so
lib/zynqmp/libipsecctrl.a
lib/zynqmp/libipsecctrl.so
```

Temporary object trees are removed after successful library creation.

From `app/`, `make` builds the required host library first and then creates
`app/bin/x86_64/ipsec_app`. `make zynqmp` does the same for the aarch64 target.

### CMake helper

From `src/`:

```sh
./cmake_build.sh host
./cmake_build.sh zynqmp
./cmake_build.sh all
./cmake_build.sh clean
```

The host helper performs a Release build and runs CTest. Override the aarch64
compiler with `ZYNQMP_CC=/path/to/aarch64-linux-gnu-gcc`.

For a persistent manual build tree:

```sh
cmake -S src -B .build/host \
    -DCMAKE_BUILD_TYPE=Release \
    -DIPSEC_BUILD_TESTS=ON \
    -DIPSEC_BUILD_APP=ON
cmake --build .build/host --parallel
ctest --test-dir .build/host --output-on-failure
```

Set `IPSEC_BUILD_LIVE_TESTS=ON` to compile the privileged one-packet diagnostic
under `tests/integration`. It is intentionally not registered with CTest.

## Verification scope

Unit tests cover VICI codecs/session serialization, XFRM and route parsers,
kernel-libipsec TUN selection, protected filter construction, NFQUEUE inner-IPv4
validation, app config/commands, error paths, rollback, cleanup, and the eight
backend/path dispatch combinations with deterministic OS seams.

The eight-combination test validates configuration selection, dispatch,
mode-mismatch errors, status, backend mismatch, partial-initialization rollback,
and idempotent cleanup. It does not prove actual encryption, decryption, TC
redirect, NFQUEUE hook placement, no-clone behavior, or packet content across
two Linux hosts.

Before production use, run privileged Linux live tests for every intended
backend/path combination and verify:

- real VICI connection and IKE/CHILD establishment;
- protected packet content and absence on ordinary NIC egress;
- submitted packet authentication/decryption and anti-replay behavior;
- plain packet equality with the expected entire inner IPv4 packet;
- absence of duplicate plain delivery to Linux sockets;
- malformed/authentication-failed/replayed ESP never reaches the plain API;
- timeout, queue overflow, application crash, rollback, and cleanup behavior;
- XFRM policy matching or kernel-libipsec TUN ingress selection;
- reconnect, rekey, repeated lifecycle, and 1:N behavior where applicable.

Current repository verification is **static/unit validated; Linux-live
validation of the new APPLICATION paths is pending** unless accompanied by a
separate environment-specific test report.

## Dependency and license boundary

The library links only the platform C and pthread runtimes. It does not link
`libstrongswan`, `libcharon`, strongSwan `libipsec`, or strongSwan's GPL VICI
client. Verify a built shared object with `readelf -d`, `ldd`, and `nm -D` in the
target environment.

Project licensing and dependency notices are in `LICENSE`, `NOTICE`, and
`THIRD_PARTY_NOTICES.md`. Shipping strongSwan, Linux, PetaLinux, or other
components creates separate compliance obligations for those components.
