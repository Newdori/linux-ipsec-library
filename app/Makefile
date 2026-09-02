TARGET ?= x86_64
CROSS_COMPILE ?=
ZYNQMP_CROSS_COMPILE ?= aarch64-linux-gnu-
SYSROOT ?=

ifneq ($(filter default undefined,$(origin CC)),)
CC = $(CROSS_COMPILE)gcc
endif

MKDIR_P ?= mkdir -p
RM_RF ?= rm -rf

CPPFLAGS += -I../include -I.
CFLAGS += -g -O2 -std=c11
CFLAGS += -Wall -Wextra -Wpedantic -Werror
CFLAGS += -D_POSIX_C_SOURCE=200809L
LDLIBS += -lpthread -ldl

BUILD_ID ?= $(shell git -C .. describe --always --dirty 2>/dev/null)
ifeq ($(strip $(BUILD_ID)),)
BUILD_ID := unknown
endif
CPPFLAGS += -DNATIVE_APP_BUILD_ID=\"$(BUILD_ID)\"

ifneq ($(strip $(SYSROOT)),)
CPPFLAGS += --sysroot=$(SYSROOT)
LDFLAGS += --sysroot=$(SYSROOT)
endif

ifeq ($(TARGET),zynqmp)
LIBRARY_TARGET = zynqmp
LIBRARY = ../lib/zynqmp/libipsecctrl.a
else ifeq ($(TARGET),x86_64)
LIBRARY_TARGET = host
LIBRARY = ../lib/x86_64/libipsecctrl.a
else
$(error Unsupported TARGET '$(TARGET)'; use x86_64 or zynqmp)
endif

OBJECT_DIR = obj/$(TARGET)
OUTPUT_DIR = bin/$(TARGET)
APPLICATION = $(OUTPUT_DIR)/ipsec_app

SOURCES = \
	algorithm_capability.c \
	algorithm_catalog.c \
	algorithm_report.c \
	algorithm_runner.c \
	cli.c \
	command.c \
	config.c \
	datapath.c \
	packet.c \
	lifecycle.c \
	peer.c \
	state.c \
	show.c \
	main.c

OBJECTS = $(patsubst %.c,$(OBJECT_DIR)/%.o,$(SOURCES))
DEPFILES = $(OBJECTS:.o=.d)
CLEAN_REQUESTED = $(filter clean,$(MAKECMDGOALS))

.PHONY: all host zynqmp build library clean clean_host clean_zynqmp \
	clean-host clean-zynqmp

all: host

host:
ifeq ($(CLEAN_REQUESTED),)
	$(MAKE) build TARGET=x86_64 CROSS_COMPILE="$(CROSS_COMPILE)" \
		SYSROOT="$(SYSROOT)"
else
	@:
endif

zynqmp:
ifeq ($(CLEAN_REQUESTED),)
	$(MAKE) build TARGET=zynqmp \
		CROSS_COMPILE="$(if $(strip $(CROSS_COMPILE)),$(CROSS_COMPILE),$(ZYNQMP_CROSS_COMPILE))" \
		SYSROOT="$(SYSROOT)"
else
	@:
endif

build: $(APPLICATION)

library:
ifeq ($(TARGET),zynqmp)
	$(MAKE) -C ../src zynqmp ZYNQMP_CC="$(CC)" \
		ZYNQMP_AR="$(CROSS_COMPILE)ar" \
		ZYNQMP_RANLIB="$(CROSS_COMPILE)ranlib"
else
	$(MAKE) -C ../src host HOST_CC="$(CC)" \
		HOST_AR="$(if $(strip $(CROSS_COMPILE)),$(CROSS_COMPILE)ar,ar)" \
		HOST_RANLIB="$(if $(strip $(CROSS_COMPILE)),$(CROSS_COMPILE)ranlib,ranlib)"
endif

$(APPLICATION): library $(OBJECTS)
	@$(MKDIR_P) $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBRARY) $(LDLIBS)

$(OBJECT_DIR)/%.o: %.c
	@$(MKDIR_P) $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -o $@ -c $<

-include $(DEPFILES)

clean:
ifeq ($(filter host zynqmp,$(MAKECMDGOALS)),host)
	$(MAKE) clean_host
else ifeq ($(filter host zynqmp,$(MAKECMDGOALS)),zynqmp)
	$(MAKE) clean_zynqmp
else
	$(MAKE) clean_host clean_zynqmp
endif

clean_host:
	$(RM_RF) obj/x86_64 bin/x86_64

clean_zynqmp:
	$(RM_RF) obj/zynqmp bin/zynqmp

clean-host: clean_host

clean-zynqmp: clean_zynqmp
