# Third-party notices

## strongSwan

strongSwan is a separate runtime program and is not included or linked into
`libipsec`. The library communicates with `charon` over the VICI Unix
socket protocol. The open-source strongSwan distribution is licensed under
GPLv2; commercial licensing is also offered by the strongSwan project.

- https://www.strongswan.org/license.html

## Linux UAPI

The library includes Linux userspace API headers supplied by the target
toolchain for Netlink, XFRM, routing, sockets and interfaces. Linux UAPI
headers use the `Linux-syscall-note` exception so they may be included by
non-GPL userspace applications. No Linux kernel source is vendored here.

- https://www.kernel.org/doc/html/latest/process/license-rules.html

This notice is informational and does not replace the license texts of the
respective upstream projects.
