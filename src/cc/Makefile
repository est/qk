# Makefile for the qk congestion controller.
#
# The BPF program has to be compiled with clang's BPF target against Linux
# uapi headers, which a macOS host does not have. The default target
# therefore builds inside a throwaway Linux container. Set CONTAINER to use a
# different runtime (podman, nerdctl, ...) and IMAGE to use a different base
# image.
#
#   make                 build qk.o and qkctl in build/
#   make container       build inside the container (same as the default)
#   make native          build on a Linux host without a container
#   make clean
#
# Two things are worked out from the machine the result will run on:
#
#   - the BPF target architecture, from the host's architecture;
#   - the shape of the kernel's congestion-control interface, because the
#     kernel's callback gained and lost arguments between versions. qk_abi
#     reads the member's prototype out of the running kernel's BTF and
#     reports how many arguments it expects.
#
# Both can be overridden: ARCH=<name> and ABI_ARGS=<n>.

CONTAINER ?= docker
IMAGE     ?= public.ecr.aws/docker/library/ubuntu:24.04

SRC_DIR   := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR := $(SRC_DIR)build
OBJ       := $(BUILD_DIR)/qk.o
AVOID_OBJ := $(BUILD_DIR)/qk_avoid.o
ABI_TOOL  := $(BUILD_DIR)/qk_abi
CTL       := $(BUILD_DIR)/qkctl

# The BPF target architecture: x86_64 -> x86, aarch64 -> arm64, and so on.
UNAME_M := $(shell uname -m)
# The case statement has to stay on one line: make folds the backslash
# continuations of a $(shell ...) into spaces before the shell sees them,
# which would break the case.
ARCH ?= $(shell case "$(UNAME_M)" in x86_64) echo x86 ;; aarch64|arm64) echo arm64 ;; armv7l|armv7) echo arm ;; ppc64le) echo powerpc ;; s390x) echo s390 ;; riscv64) echo riscv ;; *) echo "" ;; esac)

ifeq ($(strip $(ARCH)),)
$(error unsupported architecture '$(UNAME_M)'; set ARCH= explicitly)
endif

# The fallback when the kernel's interface cannot be read: the newer shape.
ABI_ARGS ?= 4

# The BPF_CFLAGS are assembled here but the ABI is only known inside the
# container, where the helper is built and run.
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
              -Wno-unused-parameter \
              -I$(SRC_DIR) -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu
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
		cc -std=gnu11 -O2 -I/src $(SRC_DIR)qk_abi.c -o /out/qk_abi \
			-lbpf -lelf -lz; \
		abi=$$(/out/qk_abi 2>/dev/null || echo 4); \
		echo "kernel congestion-control interface: $$abi arguments"; \
		clang $(BPF_CFLAGS) -DQK_ABI_ARGS=$$abi -c /src/qk.c -o /out/qk.o; \
		clang $(BPF_CFLAGS) -DQK_ABI_ARGS=$$abi -DQK_USE_CONG_CONTROL=0 \
			-c /src/qk.c -o /out/qk_avoid.o; \
		cc $(HOST_CFLAGS) /src/qkctl.c -o /out/qkctl -lbpf -lelf -lz; \
	'
	@echo "built $(OBJ) and $(CTL)"

native:
	@mkdir -p $(BUILD_DIR)
	cc $(HOST_CFLAGS) $(SRC_DIR)qk_abi.c -o $(ABI_TOOL) -lbpf -lelf -lz
	@abi=$$($(ABI_TOOL) 2>/dev/null || echo $(ABI_ARGS)); \
	echo "kernel congestion-control interface: $$abi arguments"; \
	clang $(BPF_CFLAGS) -DQK_ABI_ARGS=$$abi -c $(SRC_DIR)qk.c -o $(OBJ); \
	clang $(BPF_CFLAGS) -DQK_ABI_ARGS=$$abi -DQK_USE_CONG_CONTROL=0 \
		-c $(SRC_DIR)qk.c -o $(AVOID_OBJ)
	cc $(HOST_CFLAGS) $(SRC_DIR)qkctl.c -o $(CTL) -lbpf -lelf -lz

clean:
	rm -rf $(BUILD_DIR)
