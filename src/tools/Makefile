# SPDX-License-Identifier: GPL-2.0
#
# Measurement and inspection tools.
#
#   qkbtf   - kernel BTF inspector (needs libbpf)
#   qkprobe - open-loop UDP probe (plain POSIX)
#
# The host that drives this project is macOS, which has neither linux/bpf.h
# nor libbpf, so the build has to happen inside a Linux container.  Two
# entry points are provided:
#
#   make            build natively when libbpf is available, otherwise
#                   build inside a throwaway Linux container
#   make native     force a local build (Linux host or container with libbpf)
#   make container  force a build inside a throwaway Linux container
#
# The container image and the container runtime are overridable:
#
#   make container CONTAINER=podman IMAGE=public.ecr.aws/docker/library/ubuntu:24.04
#
# Note: the Docker Hub registry is not reachable from every network; the
# public ECR mirror of the same image is used by default.

CC       ?= cc
CFLAGS   ?= -std=c11 -O2 -Wall -Wextra -g
LDFLAGS  ?=

# libbpf needs libelf and zlib.
BPF_LIBS ?= -lbpf -lelf -lz

# Container build knobs.
IMAGE     ?= public.ecr.aws/docker/library/ubuntu:24.04
CONTAINER ?= docker

# Packages installed inside the container.  clang is not needed for these two
# tools (they are plain user space C); add it here if you also build BPF
# programs here.
CONTAINER_PKGS ?= gcc libc6-dev libbpf-dev libelf-dev zlib1g-dev make pkg-config

HOST_UID := $(shell id -u)
HOST_GID := $(shell id -g)

BUILD_DIR := build

BINARIES := $(BUILD_DIR)/qkbtf $(BUILD_DIR)/qkprobe

# Can we build against libbpf right here?  A tiny compile test is the most
# reliable answer; pkg-config may not even be installed.  (-include is used
# instead of a #include line so that make does not see a comment.)
HAVE_LIBBPF := $(shell printf 'int main(void){return 0;}\n' | $(CC) -x c - -include bpf/libbpf.h -o /dev/null $(BPF_LIBS) >/dev/null 2>&1 && echo yes || echo no)

.PHONY: all build native container clean help

all: build

# Build natively if we can, otherwise use the container.
ifeq ($(HAVE_LIBBPF),yes)
build: native
else
build: container
endif

native: $(BINARIES)

$(BUILD_DIR)/qkbtf: qkbtf.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(BPF_LIBS)

$(BUILD_DIR)/qkprobe: qkprobe.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build inside a throwaway Linux container.  The source directory is mounted
# read/write, so the binaries end up in ./build/ on the host; they are
# chowned back to the invoking user afterwards.
container:
	$(CONTAINER) run --rm \
		-v "$(CURDIR):/work" \
		-w /work \
		-e HOST_UID=$(HOST_UID) \
		-e HOST_GID=$(HOST_GID) \
		$(IMAGE) \
		bash -lc 'set -e; \
			export DEBIAN_FRONTEND=noninteractive; \
			apt-get update; \
			apt-get install -y --no-install-recommends $(CONTAINER_PKGS); \
			make native; \
			chown -R $$HOST_UID:$$HOST_GID /work/build 2>/dev/null || true'

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "targets:"
	@echo "  build      build qkbtf and qkprobe into $(BUILD_DIR)/"
	@echo "              (native when libbpf is available, container otherwise)"
	@echo "  native     force a local build (needs libbpf and the bpf headers)"
	@echo "  container  build inside a throwaway Linux container ($(IMAGE))"
	@echo "  clean      remove $(BUILD_DIR)/"
	@echo ""
	@echo "variables: CC, CFLAGS, LDFLAGS, BPF_LIBS, IMAGE, CONTAINER"
	@echo "libbpf detected on this host: $(HAVE_LIBBPF)"
