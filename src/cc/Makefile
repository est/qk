# Makefile for the qk congestion controller.
#
# The BPF program has to be compiled with clang's BPF target against Linux
# uapi headers, which a macOS host does not have. The default target therefore
# builds inside a throwaway Linux container. Set CONTAINER to use a different
# runtime (podman, nerdctl, ...) and IMAGE to use a different base image.
#
#   make                 build qk.o and qkctl in build/
#   make container       build inside the container (same as the default)
#   make native          build on a Linux host without a container
#   make clean

CONTAINER ?= docker
IMAGE     ?= public.ecr.aws/docker/library/ubuntu:24.04

SRC_DIR   := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR := $(SRC_DIR)build
OBJ       := $(BUILD_DIR)/qk.o
CTL       := $(BUILD_DIR)/qkctl

# NAME is the name the kernel registers the controller under. The kernel's
# limit is 16 bytes including the terminator, and a registered name cannot be
# replaced in place, so a second build needs a second name.
NAME      ?= qk

# The BPF_PROG macro introduces a context parameter that most callbacks do
# not use, so unused parameters are not worth a warning here.
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_arm64 -Wno-unused-parameter \
              -DQK_CC_NAME=$(NAME) \
              -I$(SRC_DIR) -I/usr/include -I/usr/include/aarch64-linux-gnu
HOST_CFLAGS := -std=gnu11 -D_GNU_SOURCE -O2 -g -Wall -Wextra -I$(SRC_DIR)

.PHONY: all build container native clean

all: container

build: container

container:
	@mkdir -p $(BUILD_DIR)
	$(CONTAINER) run --rm -v $(SRC_DIR):/src -v $(BUILD_DIR):/out \
		$(IMAGE) sh -c '\
		set -e; \
		mkdir -p /out; \
		apt-get update -qq >/dev/null 2>&1; \
		apt-get install -y -qq --no-install-recommends \
			clang llvm libbpf-dev gcc make pkg-config \
			libelf-dev zlib1g-dev >/dev/null 2>&1; \
		clang $(BPF_CFLAGS) -c /src/qk.c -o /out/qk.o; \
		gcc $(HOST_CFLAGS) /src/qkctl.c -o /out/qkctl -lbpf -lelf -lz; \
	'
	@echo "built $(OBJ) and $(CTL)"

native:
	@mkdir -p $(BUILD_DIR)
	clang $(BPF_CFLAGS) -c $(SRC_DIR)qk.c -o $(OBJ)
	gcc $(HOST_CFLAGS) $(SRC_DIR)qkctl.c -o $(CTL) -lbpf -lelf -lz

clean:
	rm -rf $(BUILD_DIR)
