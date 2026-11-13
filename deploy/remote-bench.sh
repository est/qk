#!/bin/sh
# remote-bench.sh — build, load and benchmark the qk congestion control on a
# remote Linux host, over a plain shell session.
#
# The host needs a Linux kernel with the BPF congestion-control interface.
# Check with:
#     grep -c bpf_tcp_ca /proc/kallsyms
# and a kernel BTF, which the build needs:
#     ls -l /sys/kernel/btf/vmlinux
#
# The build needs clang and libbpf's headers. On Debian and Ubuntu:
#     apt-get install -y clang libbpf-dev
#
# Usage:
#     remote-bench.sh build            compile the BPF object and the loader
#     remote-bench.sh load             register the controller
#     remote-bench.sh unload           release it
#     remote-bench.sh status           what the kernel offers, and what is pinned
#     remote-bench.sh bench --host H --port P [--cc a,b,c] [--duration S]
#                                     [--repeat N] [--bytes N]
#     remote-bench.sh local --cc a,b,c [--duration S] [--repeat N]
#                                     compare over the loopback
#
# Everything is a parameter; the defaults are documented here and nothing
# machine-specific is baked in.

set -eu

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
BUILD_DIR="${BUILD_DIR:-$REPO_DIR/build}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/qk}"
HOST="${HOST:-}"
PORT="${PORT:-443}"
PATH_="${PATH_:-/}"
DURATION="${DURATION:-10}"
REPEAT="${REPEAT:-3}"
BYTES="${BYTES:-200000000}"
CCS="${CCS:-cubic,bbr,qk}"
SKIP_MISSING="${SKIP_MISSING:-0}"

usage() {
	sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
}

log() { printf '%s\n' "$*" >&2; }
die() { printf 'remote-bench: %s\n' "$*" >&2; exit 1; }

need() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is not installed"
}

do_build() {
	need clang
	need cc
	[ -r /sys/kernel/btf/vmlinux ] || die "no kernel BTF at /sys/kernel/btf/vmlinux"
	mkdir -p "$BUILD_DIR"

	# The shape of the kernel's congestion-control interface is worked out
	# from the running kernel: qk_abi reads the member's prototype out of
	# the BTF and reports how many arguments it expects.
	cc -std=gnu11 -O2 -I "$REPO_DIR/src/cc" "$REPO_DIR/src/cc/qk_abi.c" \
		-o "$BUILD_DIR/qk_abi" -lbpf -lelf -lz
	abi=$("$BUILD_DIR/qk_abi" 2>/dev/null || echo 4)
	log "kernel congestion-control interface: $abi arguments"

	arch=$(uname -m)
	case "$arch" in
	x86_64) bpfarch=x86 ;;
	aarch64|arm64) bpfarch=arm64 ;;
	armv7l|armv7) bpfarch=arm ;;
	ppc64le) bpfarch=powerpc ;;
	s390x) bpfarch=s390 ;;
	riscv64) bpfarch=riscv ;;
	*) die "unsupported architecture $arch" ;;
	esac

	cflags="-O2 -g -target bpf -D__TARGET_ARCH_$bpfarch -Wno-unused-parameter"
	inc="-I$REPO_DIR/src/cc -I/usr/include -I/usr/include/$(uname -m)-linux-gnu"

	# The primary object works through cong_control and owns the pacing
	# rate. The fallback works through the additive-increase callback, for
	# kernels whose list of writable fields does not include the pacing
	# rate.
	clang $cflags $inc -DQK_ABI_ARGS="$abi" -c "$REPO_DIR/src/cc/qk.c" \
		-o "$BUILD_DIR/qk.o"
	clang $cflags $inc -DQK_ABI_ARGS="$abi" -DQK_USE_CONG_CONTROL=0 \
		-c "$REPO_DIR/src/cc/qk.c" -o "$BUILD_DIR/qk_avoid.o"
	cc -std=gnu11 -D_GNU_SOURCE -O2 -Wall -Wextra -I"$REPO_DIR/src/cc" \
		"$REPO_DIR/src/cc/qkctl.c" -o "$BUILD_DIR/qkctl" -lbpf -lelf -lz
	log "built $BUILD_DIR/qk.o, $BUILD_DIR/qk_avoid.o and $BUILD_DIR/qkctl"
}

do_load() {
	[ -x "$BUILD_DIR/qkctl" ] || die "run '$0 build' first"
	mkdir -p "$PIN_DIR" 2>/dev/null || true
	"$BUILD_DIR/qkctl" load --object "$BUILD_DIR/qk.o" \
		--fallback "$BUILD_DIR/qk_avoid.o" --pin-dir "$PIN_DIR" --daemon
	"$BUILD_DIR/qkctl" list
}

do_unload() {
	[ -x "$BUILD_DIR/qkctl" ] || die "run '$0 build' first"
	"$BUILD_DIR/qkctl" unload --pin-dir "$PIN_DIR" || true
}

do_status() {
	[ -x "$BUILD_DIR/qkctl" ] || die "run '$0 build' first"
	echo "kernel:      $(uname -r)"
	echo "bpf_tcp_ca:  $(grep -c bpf_tcp_ca /proc/kallsyms 2>/dev/null || echo 0) symbols"
	"$BUILD_DIR/qkctl" list
	echo "pinned under $PIN_DIR:"
	ls -l "$PIN_DIR" 2>/dev/null || echo "  (nothing)"
}

do_bench() {
	[ -x "$BUILD_DIR/tcperf" ] || die "the benchmark tool is missing; build it"
	"$BUILD_DIR/tcperf" --help >/dev/null 2>&1 || true
	"$BUILD_DIR/tcperf" bench --host "$HOST" --port "$PORT" --path "$PATH_" \
		--cc "$CCS" --duration "$DURATION" --repeat "$REPEAT" \
		--bytes "$BYTES" --skip-missing "$SKIP_MISSING"
}

do_local() {
	[ -x "$BUILD_DIR/tcperf" ] || die "the benchmark tool is missing; build it"
	"$BUILD_DIR/tcperf" local --cc "$CCS" --duration "$DURATION" \
		--repeat "$REPEAT" --skip-missing "$SKIP_MISSING"
}

[ $# -ge 1 ] || { usage; exit 2; }
cmd="$1"
shift

while [ $# -gt 0 ]; do
	case "$1" in
	--host) HOST="$2"; shift 2 ;;
	--port) PORT="$2"; shift 2 ;;
	--path) PATH_="$2"; shift 2 ;;
	--cc) CCS="$2"; shift 2 ;;
	--duration) DURATION="$2"; shift 2 ;;
	--repeat) REPEAT="$2"; shift 2 ;;
	--bytes) BYTES="$2"; shift 2 ;;
	--skip-missing) SKIP_MISSING=1; shift ;;
	-h|--help) usage; exit 0 ;;
	*) die "unknown option '$1'" ;;
	esac
done

case "$cmd" in
build) do_build ;;
load) do_load ;;
unload) do_unload ;;
status) do_status ;;
bench) [ -n "$HOST" ] || die "--host is required"; do_bench ;;
local) do_local ;;
*) usage; exit 2 ;;
esac
