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

The protected path owns only its TUN and reserved filters. It does not add
routes, addresses, firewall rules, or qdiscs. The configured TC priority pair and the
library handle namespace must be reserved for the context. Connection load
installs a peer filter pair, connection unload removes it, and failed loads are
rolled back. Stop traffic and terminate affected SAs before context destruction;
cleanup retries removal of every registered peer filter.

Before bringing its own TUN UP, the library disables IPv6 on that endpoint and
sets its IPv4 `rp_filter=2` (loose reverse-path validation), then reads it back.
It also assigns **127.0.0.1/32, scope host**, only to that private TUN. This
loopback anchor is not an IKE/ESP endpoint, traffic selector or application
address and requires no additional config field. Linux source validation can
still reject loose-RPF ingress on an **unnumbered** interface when the reverse
route uses the NIC (`fib_validate_source`, `no_addr` branch). The anchor avoids
that branch without duplicating a physical endpoint or disabling RPF globally.
The kernel creates a TUN-local host route; it does not create a connected peer
subnet route. `route_localnet` is not enabled. The address/host route disappear
with the owned non-persistent TUN. Readiness also verifies the address and /32
mask; it does not overwrite an unexpected pre-existing address.
ESP reinjected through the TUN has a source normally reached through the physical
NIC; strict reverse-path filtering may drop it before charon receives it. Only
the exclusively created, non-persistent TUN is changed. Global `all`/`default`,
the physical NIC, charon's TUN, peer routes and firewall rules are not modified.
Failure to configure/verify the setting fails initialization and cleans up the
owned endpoint. Path-status queries also reject effective strict filtering
(`max(all, interface)=1`) if another actor changes it later. Loose validation
still requires a reverse route; it is not an authentication or firewall bypass.
The per-device setting disappears with the owned TUN on normal teardown.

This first implementation is IPv4 raw ESP only. NAT-T/UDP-encapsulated ESP,
fragmented outer IPv4 and hardware-offloaded XFRM SAs are rejected. One context
supports up to 256 connection-scoped peers. kernel-libipsec protected delivery
requires strongSwan 5.9.11 or newer with the plugin's raw-ESP support enabled.
These requirements do not apply to a `SYSTEM` protected path.

## Plain APPLICATION implementation

Plain delivery uses raw `NETLINK_NETFILTER`/NFQUEUE without linking a GPL
netfilter client library. The application selects a nonzero queue number.
For the kernel-libipsec backend, the diagnostic application enables
library-owned rules: a dedicated IPv4 nftables table/base chain is created
through the Linux Netlink UAPI and one scoped rule is installed for each
loaded connection:

- kernel-libipsec backend: select only packets entering from the discovered or
  configured charon-owned TUN whose source/destination match that connection's
  remote/local traffic selectors.

External library users may leave `bManagePlainNetfilterRule=false` and
provision an equivalent OS-owned rule. XFRM plain-APPLICATION selection remains
OS-owned because it must additionally match the actual inbound IPsec policy.

Do not configure a queue-bypass/accept fallback for this path. The library
copies a validated complete IPv4 packet and then sends an `NF_DROP` verdict.
Consequently a successfully returned packet belongs to the application and is
not also delivered through the Linux stack. Malformed, truncated, wrong-TUN,
IPv6, and undersized-buffer cases are rejected; queued packets with a usable ID
are dropped even when parsing fails.

The managed kernel-libipsec rule is acknowledged by the kernel before
`connection load` succeeds and is removed on connection unload/deinit. It uses
a library-specific table and never invokes `iptables` or `nft`. The application
must run with the Netfilter administration capability. For an OS-owned rule,
queue binding alone still does not prove rule selection. The library always
checks the NFQUEUE ingress ifindex against the selected charon TUN.

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
through the host. In kernel-libipsec APPLICATION mode this selects the hook of
the library-owned base chain.

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

From `app/`, use `-c` for the role-specific configuration and `-v` for verbose
logging (put startup options before any one-shot command):

```sh
sudo ./bin/x86_64/ipsec_app -c ./config/initiator.conf -v
sudo ./bin/x86_64/ipsec_app -c ./config/responder.conf -v
```

Use the appropriate command on each PC and save the edited role-specific
example as that `.conf` file first. `--app-config` and `--verbose` remain
compatibility aliases; `--config` retains the legacy combined-config behavior.

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

The initiator peer table rejects overlapping remote traffic-selector networks
owned by different peers. The comparison uses IPv4/IPv6 CIDR ranges, so exact
duplicates and subnet containment are conflicts, while adjacent subnets and
selectors from different address families are allowed. An active peer must be
torn down before its remote traffic selector can be changed.

All ordinary connection, credential, IKE, CHILD, rekey, show, loop, and
algorithm-test commands remain available. Algorithm tests support both
`SYSTEM/SYSTEM` (existing UDP control/counter verification) and
`APPLICATION/APPLICATION` (TCP control/ESP relay and decrypted payload comparison).
Mixed packet paths are still manual diagnostic workflows.

### Session shutdown and ownership

Interactive `quit` and `exit` now perform normal cleanup by default
(`terminate_on_exit=true`). Stop externally generated test traffic first.
The app stops its peer listener, rejects new loads/tests, terminates all SA states
of every connection owned by this session (including connecting/rekeying SAs),
waits for disappearance, unloads the connections and its daemon PSK credentials,
then releases the context's owned packet paths and sockets. This also covers
resources loaded by `up`, `test loop` and algorithm tests, not just the selected
peer. Pending XFRM reqids are retained across cleanup retries; XFRM is queried,
never directly deleted by the app/library.

- `down` still cleans only the selected connection and its SAs, retains its
  credential, and leaves the CLI running. `credential unload` removes that
  session-owned credential; the PSK file remains untouched.
- Each shutdown attempt retries a failed peer at most three times, using the
  configured command/wait timeouts. Peer/stage/error messages identify failures.
  Failed cleanup leaves the process and remaining paths available for inspection
  and another `quit`; new registrations, loads, packet/test operations are blocked.
- `SIGTERM` and input EOF use the same normal cleanup. Ctrl-C cancels the current
  command. If stdin is permanently closed and cleanup fails, the process stays
  alive without releasing the remaining paths; resolve the issue externally and
  send SIGTERM to retry. SIGKILL/crashes/power loss cannot run orderly cleanup.
- `exit --force` (also `quit --force`) explicitly bypasses cleanup and accepts
  restoring ordinary NIC egress with possibly remaining daemon state. It is not
  a successful cleanup or a normal recovery procedure.
- SYSTEM interactive sessions may explicitly set `terminate_on_exit=false` to
  detach without daemon cleanup. APPLICATION sessions always require cleanup;
  this setting cannot disable their safety checks. SYSTEM one-shot commands
  retain their existing behavior (e.g. `load` must not immediately unload itself).

Ownership is an in-memory, per-session ledger, not a naming-prefix wildcard.
Pre-existing connection/SA names are not automatically adopted or overwritten
by `connection load`. Use a different name or explicitly clean the old test
resources. VICI has no atomic ownership reservation: use exclusive connection
names and do not let another controller replace them during a session.
`ike initiate` / `child initiate` require a connection loaded by this session;
`up` does not silently adopt an existing foreign connection.
Logical `credential_id` settings remain unchanged, but the daemon credential ID
is now `ipsec-app-<session-random-id>-<record-index>` to avoid overwriting/removing
another application's PSK entry. `show credential` displays this non-secret ID.
No global `clear-creds` is used during automatic shutdown. The existing explicit
`credential clear all` command remains a daemon-wide operator action.

PSK/config files, results/logs, OS addresses/routes, charon's TUN
and service, and other applications' resources are preserved. Protected
APPLICATION retains a conservative final **all-SA** guard because removing
diversion can affect a shared egress interface: foreign remaining SAs are listed
and block exit instead of being deleted. Quiescing external traffic/controllers
is still required; an app-only check is not a crash-proof OS fail-closed policy.

### Automated APPLICATION packet verification

Use the same updated application on both peers. This is a trusted, isolated lab
test transport, **not** an authenticated management service or the production
RF/GSE/RLE transport. It relays complete protected packets only; it does not
replace charon's encryption, authentication, replay checks, or SA installation.

Prerequisites on **both** PCs:

- `datapath_backend=kernel-libipsec`, `ipsec_mode=tunnel`, and both
  `protected_packet_path=application` and `plain_packet_path=application`.
- Working raw IPv4 ESP (no NAT-T) and protected TC path. The library installs
  its own scoped post-decrypt nftables/NFQUEUE rules through Netlink; it does
  not change OS addresses/routes or execute firewall commands.
- Distinct single inner IPv4 host selectors, for example PC-A
  `local_ts=172.16.10.1/32` and PC-B `local_ts=172.16.20.1/32`. Each local inner
  address must actually be assigned to its own PC (e.g. on `lo`). Peer registration
  exchanges the remote selector. Neither inner address may equal either outer
  endpoint. The library still supports broader selectors; this automatic probe
  intentionally requires a single host per side to avoid guessing probe sources.
- With local host probes, use `plain_netfilter_hook=input`. FORWARD remains for
  separate routed-network diagnostics.
- TCP `39001` reachable between outer addresses (`--port` overrides it). In
  APPLICATION mode **both test control and ESP relay use this TCP connection**;
  UDP test control is not used. Peer registration remains TCP `39002` by default.
- No other traffic/readers on the tested context/queues. Plain probes use UDP
  port `48150`, constrained to the discovered charon TUN, never ordinary NIC
  fallback. Do not run the manual `packet *-receive` commands at the same time.

After registering/selecting the peer, terminate any existing test IKE/CHILD SA
and unload its connection on **both** PCs before starting. The runner loads the
credential and per-case connection itself, then performs negotiation and cleanup.

```text
# PC-B first (responder)
test algorithm serve

# PC-A (initiator): start with one case and inspect its result
test algorithm run baseline --limit 1 --stop-on-error
```

Start `test algorithm serve` again on PC-B before **each** PC-A run:

```text
test algorithm run baseline --all --stop-on-error
test algorithm run exhaustive-ike --all --stop-on-error
test algorithm run exhaustive-esp --all --stop-on-error
```

APPLICATION runs now stop after the first `FAIL_DATA_PATH` packet test by
default, after saving that case and performing cleanup/control completion.
This also applies to `--all`: it prevents repeating the same packet timeout for
every proposal on an unverified path. Use `--continue-on-data-path-error`
explicitly only when intentionally collecting subsequent packet-path failures.
`--continue-on-error` continues negotiation/control failures but does not bypass
this data-path circuit breaker. `--stop-on-error` stops on
other failures too; SYSTEM and expected-unsupported behavior are unchanged.
Ctrl-C cleanup queries the actual remaining SAs at least once. An interrupted
wait with SAs still present reports cancellation, not a fabricated VICI timeout.

For every supported case, the runner sends two 128-byte probe payloads in each
direction, receives their completed ESP through `ReceiveIpsecProtectedPacket`,
transfers them over TCP, calls the peer's `SubmitIpsecProtectedPacket`, then
compares the full decrypted IPv4/UDP framing and payload from
`ReceiveIpsecPlainPacket`. A fresh per-case nonce and sequence distinguish stale
or unrelated packets. PASS requires both directions to verify **and** the
existing IKE/CHILD/install/counter checks to succeed. TCP delivery alone is not
proof of IPsec success. Unsupported proposals retain their existing classification.

The CLI prints each blocking packet stage and its remaining case data timeout
(control acknowledgements have a separate bounded 5-second grace). In
`application_packet.log`, `protected_relay_send` records the TCP send separately
from peer plaintext verification. `protected_submit` success means the complete
packet was written to the protected TUN, **not** that charon authenticated or
decrypted it. The log also records before/after `rp_filter` values, TUN RX/drop
counters, NFQUEUE queue metadata and bounded IPv4 statistics. These counters
are host/namespace diagnostics, not exclusive per-test traffic proof.
Expected INPUT/TUN/inner-address/queue settings record whether the rule is
library-owned and kernel-acknowledged. For OS-owned mode, queue binding still
does not verify an administrator-provisioned firewall rule.
No plaintext, ESP contents, PSK or derived keys are dumped.

For a `plain_receive` timeout, compare the post-failure `sa_snapshot.txt`:
zero inbound CHILD counters warrant checking protected TUN ingress, reverse-path
filtering, firewall handling and charon ESP/authentication logs first; increased
inbound counters warrant checking the charon TUN and post-decrypt NFQUEUE path.
Do not increase the timeout or flush the firewall as a substitute for locating
the drop. APPLICATION failure reports preserve the first local packet error;
a peer's echoed ABORT no longer erases it. `application_packet_test.local_error`
distinguishes local failure from an error received from the peer.

Existing dated result directories and `results.json` are retained (schema 9).
Each executed packet stage adds `application_packet.log` (elapsed time, stage,
error and packet metadata), `library_packet.log` (bounded protected-TUN packet
classification metadata), and `packet_evidence.csv` (one row per attempted
direction/probe). JSON `application_packet_test` includes the same packet evidence and the
expected inbound/outbound SPI from the selected CHILD SA. Captured/relayed raw ESP
must have valid IPv4 framing and the expected SPI; this header check is not an
independent cryptographic check. Charon remains responsible for authentication
and decryption. The local post-decrypt packet must match the expected IP/UDP
addresses, ports, nonce, sequence and all 128 payload bytes.

The library-owned protected TUN disables IPv6 before it is brought up so that
locally generated IPv6 control traffic is not confused with captured IPv4 RAW
ESP traffic. `library_packet.log` never stores packet payloads, PSKs, or private
key material.

The console, run log, per-case `application.log`, `result_summary.txt` and packet log show
`ESP_CAPTURE`, `ESP_SUBMIT`, `PLAIN_DELIVERY`, `PAYLOAD_MATCH` and an overall
`proof`. Each check reports PASS/FAIL/NOT_RUN and successes out of two packets.
NOT_RUN means the stage was never attempted (for example after negotiation
failed), not a successful check. Overall PASS cannot be derived from SA counters
alone: all four local probe records and the peer's plaintext acknowledgements
must be complete. SPI/ESP sequence/packet lengths and boolean outcomes are stored;
PSKs and plaintext payload dumps are not. Timeouts and
Ctrl-C are bounded; a broken/partial TCP frame closes the test transport. The
matrix stops if cleanup cannot be confirmed, even when continuing case failures
was requested. Inspect and clean the peer before restarting after such a failure.

Manual `protected-receive` creates its file before waiting. If receive fails,
the retained file may be empty/incomplete and **must not be submitted**. A
`file read failed` on that file is not a decryption result. The automatic test
does not use these files and records a receive failure without submitting it.
An unsupported protected packet is still rejected (not treated as a PASS); the
library logger now records bounded header metadata before discarding its length.

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

Set `IPSEC_BUILD_LIVE_TESTS=ON` to compile the privileged diagnostics under
`tests/integration`. They are intentionally not registered with CTest.
The TUN regression test creates its own disposable network namespace before
changing anything. It reproduces an unnumbered loose-RPF ingress drop, then
verifies delivery after the real library's host-/32 initialization. It uses UDP
to isolate Linux ingress, not to claim ESP/charon/NFQUEUE end-to-end validation.
From the repository root on Linux:

```sh
cmake -S src -B .build/tun-ingress -DIPSEC_BUILD_LIVE_TESTS=ON -DIPSEC_BUILD_APP=OFF
cmake --build .build/tun-ingress --target test_live_tun_ingress --parallel
sudo ./.build/tun-ingress/test_live_tun_ingress
```

Exit 77 means namespace isolation is unavailable; no host interfaces are changed.

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
