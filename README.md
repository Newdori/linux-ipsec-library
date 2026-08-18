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
- PSK file generation and secure sensitive-buffer clearing
- Interactive `ipsec_app` for configuration, connection, credential, IKE,
  CHILD, peer, status, loop, and algorithm test operations
- Static and shared library outputs: `libipsec.a` and `libipsec.so`

The `src/datapath/kernel_libipsec` and `src/crypto` directories reserve the
future user-space ESP and KCMVP integration boundaries. They are not part of
the current build.

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
