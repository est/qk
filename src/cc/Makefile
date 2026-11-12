# Makefile for the qk congestion controller.
#
# WHAT THIS BUILDS
#   build/qk.o    the BPF program (BPF_PROG_TYPE_STRUCT_OPS) that implements
#                 the congestion control law
#   build/qkctl   the loader: registers the controller with the kernel, sets
#                 the tunables, reads the state back
#
# HOW TO BUILD
#   make                 build in a container (works on any host)
#   make native          build on a Linux host, without a container
#   make image           build a container image that has the tool chain
#   make clean
#
# WHY A CONTAINER IS THE DEFAULT
#   The BPF program has to be compiled with clang's BPF target against Linux
#   uapi headers, which a macOS host does not have.  The default target
#   therefore builds inside a throwaway Linux container.  A Linux host that
#   has clang and the libbpf headers can build natively instead:
#
#       make native
#
# ARCHITECTURE
#   The BPF program has to be compiled for the architecture of the kernel
#   that will load it, which is the architecture of the machine that runs
#   the build.  The mapping is derived from "uname -m":
#
#       x86_64   -> x86        aarch64 -> arm64     armv7l -> arm
#       ppc64le  -> powerpc   s390x   -> s390
#
#   An architecture that is not in that list is an error; the BPF target
#   architecture can be set explicitly:
#
#       make ARCH=x86
#
#   The container build takes the include directory of the container's own
#   architecture and warns when that differs from the host's.
#
# ENVIRONMENT
#   CONTAINER   container runtime                 (default: docker)
#   IMAGE       container image                    (default: ubuntu:24.04)
#   INSTALL     install the build dependencies in the container.  The
#               default is 1 for the default image (a plain Ubuntu without a
#               compiler) and 0 for an image that was named explicitly,
#               because such an image is expected to have them already.
#   TOOLCHAIN_IMAGE  the image "make image" builds (default: qk-build:24.04)
#   NAME        the name the kernel registers the controller under (qk)
#   CLANG       the compiler for the BPF program   (default: clang)
#   CC          the compiler for the loader        (default: gcc)

CONTAINER ?= docker
CLANG     ?= clang
CC        ?= gcc

# The plain Ubuntu image the container build starts from.
DEFAULT_IMAGE := public.ecr.aws/docker/library/ubuntu:24.04
# The image "make image" builds; it already has the tool chain.
TOOLCHAIN_IMAGE ?= qk-build:24.04

# Remember where IMAGE came from before it is given its default: an image
# that was named explicitly is expected to have the tool chain already, so
# the packages are not installed again (that takes a while and needs the
# network).
IMAGE_ORIGIN := $(origin IMAGE)
IMAGE        ?= $(DEFAULT_IMAGE)

ifeq ($(filter command line environment,$(IMAGE_ORIGIN)),)
  INSTALL ?= 1
else
  INSTALL ?= 0
endif

SRC_DIR   := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR := $(SRC_DIR)build
OBJ       := $(BUILD_DIR)/qk.o
CTL       := $(BUILD_DIR)/qkctl

# NAME is the name the kernel registers the controller under. The kernel's
# limit is 16 bytes including the terminator, and a registered name cannot be
# replaced in place, so a second build needs a second name.
NAME      ?= qk

# ---------------------------------------------------------------------
# architecture
# ---------------------------------------------------------------------
#
# HOST_ARCH is what "uname -m" says.  ARCH is the BPF target architecture
# (the value of the __TARGET_ARCH_<arch> define) and ARCH_TRIPLET is the
# multiarch include directory that belongs to it.  ARCH can be set
# explicitly; the triplet is then derived from it.

HOST_ARCH := $(shell uname -m)

# host machine type -> BPF target architecture and multiarch triplet
# (aarch64 is what Linux calls it, arm64 is what macOS calls it)
ARCH_x86_64  := x86     x86_64-linux-gnu
ARCH_aarch64 := arm64   aarch64-linux-gnu
ARCH_arm64   := arm64   aarch64-linux-gnu
ARCH_armv7l  := arm     arm-linux-gnueabihf
ARCH_ppc64le := powerpc powerpc64le-linux-gnu
ARCH_s390x   := s390    s390x-linux-gnu

# BPF target architecture -> multiarch triplet (used when ARCH= is given)
TRIPLET_x86     := x86_64-linux-gnu
TRIPLET_arm64   := aarch64-linux-gnu
TRIPLET_arm     := arm-linux-gnueabihf
TRIPLET_powerpc := powerpc64le-linux-gnu
TRIPLET_s390    := s390x-linux-gnu

# An unknown architecture is not an error here: "make clean" and "make help"
# have to keep working.  The build targets refuse to build instead.
ARCH_OK := 1
ARCH_REASON :=

ifneq ($(strip $(ARCH)),)
  ARCH_TRIPLET := $(TRIPLET_$(strip $(ARCH)))
  ifeq ($(strip $(ARCH_TRIPLET)),)
    ARCH_OK     := 0
    ARCH_REASON := the BPF target architecture '$(ARCH)' is not one of x86, arm64, arm, powerpc, s390
  endif
else
  ARCH_MAP := $(ARCH_$(HOST_ARCH))
  ifneq ($(strip $(ARCH_MAP)),)
    ARCH         := $(word 1,$(ARCH_MAP))
    ARCH_TRIPLET := $(word 2,$(ARCH_MAP))
  else
    ARCH         :=
    ARCH_TRIPLET :=
    ARCH_OK      := 0
    ARCH_REASON  := the architecture of this machine ('$(HOST_ARCH)') is not one of the architectures the BPF target is known for
  endif
endif

# The BPF_PROG macro introduces a context parameter that most callbacks do
# not use, so unused parameters are not worth a warning here.
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wno-unused-parameter \
              -DQK_CC_NAME=$(NAME) \
              -I$(SRC_DIR) -I/usr/include -I/usr/include/$(ARCH_TRIPLET)
HOST_CFLAGS := -std=gnu11 -D_GNU_SOURCE -O2 -g -Wall -Wextra -I$(SRC_DIR)
# The same, for the build inside the container: the sources are mounted at
# /src there.
HOST_CFLAGS_CONTAINER := -std=gnu11 -D_GNU_SOURCE -O2 -g -Wall -Wextra -I/src

# The packages the container build installs when it has to.
PKGS := clang llvm libbpf-dev gcc make pkg-config libelf-dev zlib1g-dev

.PHONY: all build container native image check-arch clean help

all: container

build: container

# Refuse to build when the architecture could not be determined: a BPF
# program for the wrong architecture does not load, and the failure would be
# cryptic.
check-arch:
	@if [ "$(ARCH_OK)" != "1" ]; then \
		echo "error: $(ARCH_REASON)." >&2; \
		echo "       The BPF program has to be compiled for the kernel that" >&2; \
		echo "       loads it.  Set ARCH= to the BPF target architecture:" >&2; \
		echo "           make ARCH=x86       # x86_64" >&2; \
		echo "           make ARCH=arm64     # aarch64" >&2; \
		echo "           make ARCH=arm       # armv7l" >&2; \
		echo "           make ARCH=powerpc   # ppc64le" >&2; \
		echo "           make ARCH=s390      # s390x" >&2; \
		exit 1; \
	fi

container: check-arch
	@mkdir -p $(BUILD_DIR)
	$(CONTAINER) run --rm -v $(SRC_DIR):/src -v $(BUILD_DIR):/out \
		$(IMAGE) sh -c '\
		set -e; \
		mkdir -p /out; \
		if [ "$(INSTALL)" = "1" ]; then \
			apt-get update -qq >/dev/null 2>&1; \
			apt-get install -y -qq --no-install-recommends \
				$(PKGS) >/dev/null 2>&1; \
		fi; \
		m=$$(uname -m); \
		case "$$m" in \
			x86_64|amd64) t=x86_64-linux-gnu ;; \
			aarch64|arm64) t=aarch64-linux-gnu ;; \
			armv7l|armv7|armv6l) t=arm-linux-gnueabihf ;; \
			ppc64le) t=powerpc64le-linux-gnu ;; \
			s390x) t=s390x-linux-gnu ;; \
			*) t="" ;; \
		esac; \
		if [ -n "$$t" ] && [ "$$t" != "$(ARCH_TRIPLET)" ]; then \
			echo "warning: the container runs $$m, the host is $(HOST_ARCH)" >&2; \
			echo "         the object is built for the host kernel" >&2; \
		fi; \
		inc=""; \
		if [ -n "$$t" ]; then inc="-I/usr/include/$$t"; fi; \
		clang -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
			-Wno-unused-parameter -DQK_CC_NAME=$(NAME) \
			-I/src -I/usr/include $$inc \
			-c /src/qk.c -o /out/qk.o; \
		gcc $(HOST_CFLAGS_CONTAINER) /src/qkctl.c -o /out/qkctl -lbpf -lelf -lz; \
	'
	@echo "built $(OBJ) and $(CTL)"

# Build on the machine itself.  Needs clang with the BPF target and the
# libbpf headers; no container is involved.
native: check-arch
	@mkdir -p $(BUILD_DIR)
	@command -v $(CLANG) >/dev/null 2>&1 || \
		{ echo "error: $(CLANG) is not installed (clang with the BPF target is needed)" >&2; exit 1; }
	$(CLANG) $(BPF_CFLAGS) -c $(SRC_DIR)qk.c -o $(OBJ)
	$(CC) $(HOST_CFLAGS) $(SRC_DIR)qkctl.c -o $(CTL) -lbpf -lelf -lz
	@echo "built $(OBJ) and $(CTL)"

# Build an image that has the tool chain, so that the container build does
# not have to install anything:
#
#     make image
#     make container IMAGE=qk-build:24.04
image:
	@printf '%s\n' \
		'FROM $(DEFAULT_IMAGE)' \
		'RUN apt-get update && apt-get install -y --no-install-recommends $(PKGS) && rm -rf /var/lib/apt/lists/*' \
		| $(CONTAINER) build -t $(TOOLCHAIN_IMAGE) -
	@echo "built the image $(TOOLCHAIN_IMAGE)"

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "qk congestion controller"
	@echo ""
	@echo "targets:"
	@echo "  all/container  build qk.o and qkctl inside a container"
	@echo "  native         build qk.o and qkctl on this machine (no container)"
	@echo "  image          build a container image that has the tool chain"
	@echo "  clean          remove the build output"
	@echo ""
	@echo "host architecture : $(HOST_ARCH)"
	@echo "BPF target arch  : $(ARCH)"
	@echo "include triplet  : $(ARCH_TRIPLET)"
	@echo "container image  : $(IMAGE)"
	@echo "install packages : $(INSTALL)"
