# linux-ipsec-library

`linux-ipsec-library` is a reusable C11 IPsec control and status library for
Linux. It communicates with a separately running strongSwan `charon` daemon
through the VICI Unix-domain-socket protocol and reads kernel state through
Linux Netlink and `/proc` interfaces.

The library does not invoke `swanctl`, `ipsec`, `ip`, `systemctl`, or other
command-line tools. It also does not link to strongSwan GPL libraries.

## Current implementation

- VICI connection, configuration, credential, IKE SA, CHILD SA, algorithm,
  and daemon-status operations
- Read-only `NETLINK_XFRM` state and policy queries
- `/proc/net/xfrm_stat` parsing
- Read-only `NETLINK_ROUTE` interface, address, and route queries
- Runtime datapath detection for the Linux XFRM and strongSwan
  `kernel-libipsec` backends
- `kernel-libipsec` TUN-interface and route readiness inspection
- PSK file generation and secure sensitive-buffer clearing
- Interactive `ipsec_app` for configuration, connection, credential, IKE,
  CHILD, peer, status, loop, and algorithm test operations
- Static and shared library outputs: `libipsec.a` and `libipsec.so`

The `src/datapath/kernel_libipsec` directory contains status and validation
logic for strongSwan's separately running `kernel-libipsec` plugin. The
library does not copy or link strongSwan GPL code. The `src/crypto` directory
remains the reserved boundary for a future KCMVP provider integration and is
not part of the current build.

## GNU Make build

Run from the `src` directory on Ubuntu Linux:

```sh
make             # host and ZynqMP
make host        # host only
make zynqmp      # ZynqMP only
make clean       # remove all outputs
make host clean  # remove host outputs only
make zynqmp clean
```

The host results are written to `lib/x86_64/` and ZynqMP results to
`lib/zynqmp/`. Object files use `src/.build/` temporarily and are removed only
after both library files have been generated successfully.

The default cross compiler is `aarch64-linux-gnu-gcc`. It may be overridden:

```sh
make zynqmp ZYNQMP_CC=/path/to/aarch64-linux-gnu-gcc
```

## CMake build

The single helper script configures, builds, and copies the libraries:

```sh
./cmake_build.sh host
./cmake_build.sh zynqmp
./cmake_build.sh all
./cmake_build.sh clean
```

Host CMake builds also run the unit tests. Failed builds keep their temporary
directory for diagnosis; successful builds remove it.

## Interactive application

Build the application from the `app` directory. The application build first
builds the matching static library and then links only against the public API.

```sh
make host
make zynqmp
make clean
make host clean
make zynqmp clean
```

Outputs:

```text
app/bin/x86_64/ipsec_app
app/bin/zynqmp/ipsec_app
```

Start with split application and management configuration files:

```sh
./bin/x86_64/ipsec_app \
    --app-config ./config/application_initiator.conf.example \
    --management-config ./config/management.conf.example
```

Use `help` at the `ipsec>` prompt to list the interactive commands. The
application keeps configuration in memory and does not invoke strongSwan or
Linux networking command-line tools.

## kernel-libipsec backend

`kernel-libipsec` moves ESP packet processing from Linux XFRM into the
strongSwan `charon` process and sends cleartext packets through a TUN device,
normally `ipsec0`. It still uses the strongSwan `kernel-netlink` plugin as its
Linux network backend. Consequently both plugins should appear in the VICI
daemon status, while XFRM SA and policy entries are not expected.

The administrative initialization script is intentionally separate from the
library and application. Preview its changes on each endpoint first:

```sh
sudo ./strongswan_script/initialize_strongswan.sh \
    --dry-run --datapath kernel-libipsec
```

Then apply the backend and restart the installed strongSwan service:

```sh
sudo ./strongswan_script/initialize_strongswan.sh \
    --datapath kernel-libipsec --adjust-rp-filter
```

The default uses UDP-encapsulated ESP because that is the most portable
kernel-libipsec configuration. `--raw-esp` may be used only with strongSwan
5.9.11 or newer after the target network has been checked. Host-to-host
selectors that include the IKE peer are enabled by default; use
`--no-allow-peer-ts` only when traffic selectors are separate from peer
addresses.

After starting `ipsec_app`, verify backend selection before loading a
connection:

```text
ipsec> show daemon detail
ipsec> show datapath
```

The expected datapath output contains `Backend : kernel-libipsec`,
`Ready : yes`, an `ipsec0` TUN interface, and at least one route after a CHILD
SA is installed. `show xfrm` reports `not applicable` for this backend.

### Two-endpoint acceptance test

Start the initiator application first so its peer listener is active, then
start the responder application. Register the responder and run these commands
at its prompt:

```text
peer register
connection load
credential load
show datapath
show connections detail
```

At the initiator prompt, select the peer ID printed by `peer show` and run:

```text
peer show
peer select rcst-GROUP_ID-LOGON_ID
connection load
credential load
ike initiate
ike wait
child wait
show summary detail
show datapath
show ike detail
show child detail
```

Send traffic matching the configured traffic selectors from a separate shell
on either endpoint, then run `show child detail` on both endpoints. Packet and
byte counters must increase. Finally exercise rekey and repeated cleanup:

```text
child rekey
child wait
ike rekey
ike wait
test loop --count 10 --delay-ms 1000
show summary detail
```

The loop test validates IKE and CHILD objects for both backends. With XFRM it
also requires matching XFRM states and policies; with kernel-libipsec it
requires the active `ipsec0` interface and a route through that interface.
Because the TUN device is shared by the daemon, cleanup waits for the test IKE
and CHILD objects to disappear and does not require `ipsec0` itself to be
removed.

For one automated ESP acceptance case, leave the responder waiting with:

```text
ipsec> test algorithm serve --port 39001
```

Then run this at the initiator. The generated schema-version-5 `results.json`
records `datapath=kernel-libipsec`, `install_result=PASS`, and the observed TUN
route count instead of claiming that XFRM objects exist:

```text
ipsec> test algorithm run baseline --limit 1 --port 39001
```

If initialization fails, collect these diagnostics before restoring the
previous backend:

```sh
systemctl status strongswan.service --no-pager -l
journalctl -u strongswan.service -b --no-pager -n 200
swanctl --stats
```

These commands are deployment diagnostics only and are never executed by the
library or application.

## Runtime requirements

- Linux with VICI-enabled strongSwan `charon`
- A VICI socket, normally `/run/charon.vici` or `/var/run/charon.vici`
- Appropriate permissions for VICI and Netlink status operations

See `include/ipsec.h` for the public API. Internal VICI and Netlink structures
are not exposed through the public headers.

## License boundary

This project is licensed under Apache License 2.0. strongSwan and the Linux
kernel remain separate programs and retain their respective licenses. See
`NOTICE` and `THIRD_PARTY_NOTICES.md` for distribution notes.
