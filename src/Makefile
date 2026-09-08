SHELL := /bin/sh

.DEFAULT_GOAL := all

HOST_CC ?= gcc
HOST_AR ?= ar
HOST_RANLIB ?= ranlib
ZYNQMP_CC ?= aarch64-linux-gnu-gcc
ZYNQMP_AR ?= aarch64-linux-gnu-ar
ZYNQMP_RANLIB ?= aarch64-linux-gnu-ranlib

COMMON_CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -O2
COMMON_CPPFLAGS := -I../include -Iinternal -Iike/vici -Idatapath/common \
	-Idatapath/kernel_libipsec -Idatapath/xfrm -Idatapath/protected \
	-Idatapath/plain -Inetwork
COMMON_LDLIBS := -pthread

SOURCES := \
	core/buffer_validate.c \
	core/context.c \
	core/error.c \
	core/ipsec.c \
	core/log.c \
	core/netlink.c \
	core/psk.c \
	core/secure_zero.c \
	core/util.c \
	ike/vici/vici_algorithm.c \
	ike/vici/vici_client.c \
	ike/vici/vici_connection.c \
	ike/vici/vici_credential.c \
	ike/vici/vici_packet.c \
	ike/vici/vici_parser.c \
	ike/vici/vici_sa.c \
	ike/vici/vici_stats.c \
	ike/vici/vici_transport.c \
	ike/vici/vici_wait.c \
	datapath/common/datapath.c \
	datapath/common/datapath_health.c \
	datapath/common/packet_path.c \
	datapath/kernel_libipsec/kernel_libipsec_datapath.c \
	datapath/kernel_libipsec/kernel_libipsec_status.c \
	datapath/kernel_libipsec/kernel_libipsec_tun.c \
	datapath/xfrm/xfrm_backend.c \
	datapath/xfrm/xfrm_policy.c \
	datapath/xfrm/xfrm_state.c \
	datapath/xfrm/xfrm_stats.c \
	datapath/protected/protected_path.c \
	datapath/protected/system_protected_path.c \
	datapath/protected/application_protected_path.c \
	datapath/protected/application_protected_tun.c \
	datapath/protected/application_protected_filter.c \
	datapath/protected/application_protected_netlink.c \
	datapath/protected/protected_packet.c \
	datapath/plain/plain_path.c \
	datapath/plain/system_plain_path.c \
	datapath/plain/application_plain_path.c \
	datapath/plain/plain_netfilter.c \
	datapath/plain/plain_nftables.c \
	network/address.c \
	network/interface.c \
	network/route.c

PLATFORM ?= undefined
ARCH_DIRECTORY ?= undefined
BUILD_DIRECTORY := .build/$(PLATFORM)
OBJECTS := $(SOURCES:%.c=$(BUILD_DIRECTORY)/%.o)
LIBRARY_VERSION := 0.2.0
LIBRARY_SONAME := libipsecctrl.so.1
BUILD_STATIC_LIBRARY := $(BUILD_DIRECTORY)/libipsecctrl.a
BUILD_SHARED_LIBRARY := $(BUILD_DIRECTORY)/libipsecctrl.so.$(LIBRARY_VERSION)
OUTPUT_DIRECTORY := ../lib/$(ARCH_DIRECTORY)
CLEAN_REQUESTED := $(filter clean,$(MAKECMDGOALS))

.PHONY: all host zynqmp build-target clean clean-host clean-zynqmp

all: host zynqmp

host:
ifeq ($(CLEAN_REQUESTED),)
	$(MAKE) --no-print-directory PLATFORM=host ARCH_DIRECTORY=x86_64 \
		CC="$(HOST_CC)" AR="$(HOST_AR)" RANLIB="$(HOST_RANLIB)" build-target
else
	@:
endif

zynqmp:
ifeq ($(CLEAN_REQUESTED),)
	$(MAKE) --no-print-directory PLATFORM=zynqmp ARCH_DIRECTORY=zynqmp \
		CC="$(ZYNQMP_CC)" AR="$(ZYNQMP_AR)" RANLIB="$(ZYNQMP_RANLIB)" build-target
else
	@:
endif

build-target: $(BUILD_STATIC_LIBRARY) $(BUILD_SHARED_LIBRARY)
	@mkdir -p "$(OUTPUT_DIRECTORY)"
	@cp "$(BUILD_STATIC_LIBRARY)" "$(OUTPUT_DIRECTORY)/libipsecctrl.a"
	@cp "$(BUILD_SHARED_LIBRARY)" "$(OUTPUT_DIRECTORY)/libipsecctrl.so.$(LIBRARY_VERSION)"
	@ln -sfn "libipsecctrl.so.$(LIBRARY_VERSION)" "$(OUTPUT_DIRECTORY)/$(LIBRARY_SONAME)"
	@ln -sfn "$(LIBRARY_SONAME)" "$(OUTPUT_DIRECTORY)/libipsecctrl.so"
	@rm -rf "$(BUILD_DIRECTORY)"
	@printf '%s\n' "Generated $(OUTPUT_DIRECTORY)/libipsecctrl.a"
	@printf '%s\n' "Generated $(OUTPUT_DIRECTORY)/libipsecctrl.so"

$(BUILD_DIRECTORY)/%.o: %.c
	@mkdir -p "$(dir $@)"
	$(CC) $(COMMON_CPPFLAGS) $(CPPFLAGS) $(COMMON_CFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(BUILD_STATIC_LIBRARY): $(OBJECTS)
	$(AR) rcs "$@" $(OBJECTS)
	$(RANLIB) "$@"

$(BUILD_SHARED_LIBRARY): $(OBJECTS) libipsecctrl.map
	$(CC) -shared -Wl,-soname,$(LIBRARY_SONAME) -Wl,--version-script="$(CURDIR)/libipsecctrl.map" \
		-o "$@" $(OBJECTS) $(LDFLAGS) $(COMMON_LDLIBS) $(LDLIBS)

clean:
ifeq ($(filter host zynqmp,$(MAKECMDGOALS)),host)
	$(MAKE) --no-print-directory clean-host
else ifeq ($(filter host zynqmp,$(MAKECMDGOALS)),zynqmp)
	$(MAKE) --no-print-directory clean-zynqmp
else
	$(MAKE) --no-print-directory clean-host clean-zynqmp
endif

clean-host:
	@rm -rf .build/host .build/cmake/host ../lib/x86_64

clean-zynqmp:
	@rm -rf .build/zynqmp .build/cmake/zynqmp ../lib/zynqmp
