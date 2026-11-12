#!/bin/sh
#
# lab.sh - orchestration for the TCP congestion control comparison bench.
#
# WHAT THIS DOES
#   Creates a private docker network with a client and a server container,
#   shapes the client -> server path with tc/netem and runs tcperf for one
#   or more congestion control algorithms so that their raw TCP throughput
#   can be compared over an identical, controlled, lossy path.
#
#   Congestion control is selected per socket, so the BPF registered "qk"
#   algorithm has to be loaded *inside the client container* - the
#   registration is per network namespace.  See "loadcc" below.
#
# HOW TO BUILD THE TOOL
#   ./lab.sh build          # builds ./tcperf inside a container
#   make                    # same thing, on a Linux host
#
# HOW TO RUN
#   ./lab.sh up
#   ./lab.sh loss --rate 2 --delay 20 --mode per-ip --ports 1
#   ./lab.sh compare --cc reno,cubic,qk --duration 10 --repeat 3
#   ./lab.sh status
#   ./lab.sh down
#
#   BPF congestion control (per network namespace):
#   ./lab.sh loadcc --object ../cc/qk_cc.o
#   ./lab.sh unloadcc
#
# EVERYTHING IS OVERRIDABLE
#   Every name, address, port and image can be set through the environment.
#   The single block of VAR="${VAR:-default}" assignments below is the only
#   place where defaults live, so it is easy to audit and to change.
#
# NOTES
#   * The default IPv6 prefix is a documentation/ULA prefix
#     (fd00:db8:9:1::/64); it never touches a real network.
#   * The default image comes from the public ECR mirror because the Docker
#     Hub registry is not reachable from this machine.
#   * The containers and the network of the other workstream (qk-cl, qk-gw,
#     qk-bpf, qk-net) are never touched; see RESERVED_NAMES below.
#
set -eu

# ====================================================================
# configuration - every value can be overridden from the environment
# ====================================================================

# images
BENCH_IMAGE="${BENCH_IMAGE:-public.ecr.aws/docker/library/ubuntu:24.04}"
LAB_IMAGE="${LAB_IMAGE:-qkbench-lab:24.04}"
BUILD_IMAGE="${BUILD_IMAGE:-qkbench-build:24.04}"

# names (never reuse the names of the other workstream)
BENCH_NET="${BENCH_NET:-qkbench-net}"
CLIENT_NAME="${CLIENT_NAME:-qkbench-client}"
SERVER_NAME="${SERVER_NAME:-qkbench-server}"

# addressing (documentation/ULA IPv6 prefix, private IPv4 subnet)
V4_SUBNET="${V4_SUBNET:-172.31.77.0/24}"
V6_SUBNET="${V6_SUBNET:-fd00:db8:9:1::/64}"
CLIENT_V6="${CLIENT_V6:-fd00:db8:9:1::2}"
SERVER_V6="${SERVER_V6:-fd00:db8:9:1::64}"

# test parameters
PORT="${PORT:-9400}"
DURATION="${DURATION:-10}"
REPEAT="${REPEAT:-1}"
WRITE_SIZE="${WRITE_SIZE:-65536}"
SNDBUF="${SNDBUF:-65536}"
RCVBUF="${RCVBUF:-65536}"

# path impairment
LOSS_RATE="${LOSS_RATE:-1}"
LOSS_DELAY="${LOSS_DELAY:-20}"
LOSS_MODE="${LOSS_MODE:-per-ip}"
LOSS_PORTS="${LOSS_PORTS:-1}"
CLIENT_IF="${CLIENT_IF:-eth0}"

# BPF congestion control loader (lives in the bind mounted bench directory)
CC_SRC_DIR="${CC_SRC_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)/cc}"
LOADER_PATH="${LOADER_PATH:-/cc/build/qkctl}"
CC_OBJ_DIR="${CC_OBJ_DIR:-/tmp/qkbench-cc}"
LOADCC_DAEMON="${LOADCC_DAEMON:-0}"

# names that belong to another workstream and must never be touched
RESERVED_NAMES="qk-cl qk-gw qk-bpf qk-net qkbench-cl qkbench-gw"

# ====================================================================
# helpers
# ====================================================================

log() {
    printf 'lab: %s\n' "$*" >&2
}

die() {
    printf 'lab: error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat >&2 <<EOF
usage: $0 <command> [options]

commands:
  up                                       create network + client/server containers
  down                                     remove the containers and the network
  status                                   show what currently exists
  build                                    build ./tcperf (inside a container)
  loss   [--rate <pct>] [--delay <ms>]     shape the client -> server path
          [--mode per-ip|shared]
          [--ports <n>]
  compare --cc <a,b,c> [--duration <s>]     run tcperf for every algorithm
          [--repeat <n>]
  loadcc --object <path>                   load a BPF congestion control into the
                                           client container (netns local!)
  unloadcc                                 unload the BPF congestion control

environment variables (all optional, see the block of defaults at the top
of this script):
  BENCH_IMAGE   container image              (default: $BENCH_IMAGE)
  LAB_IMAGE     image with iproute2         (default: $LAB_IMAGE)
  BUILD_IMAGE   image with a C compiler     (default: $BUILD_IMAGE)
  BENCH_NET     docker network name         (default: $BENCH_NET)
  CLIENT_NAME   client container name       (default: $CLIENT_NAME)
  SERVER_NAME   server container name       (default: $SERVER_NAME)
  V4_SUBNET     IPv4 subnet of the network  (default: $V4_SUBNET)
  V6_SUBNET     IPv6 subnet of the network  (default: $V6_SUBNET)
  CLIENT_V6     client IPv6 address         (default: $CLIENT_V6)
  SERVER_V6     server IPv6 address         (default: $SERVER_V6)
  PORT          TCP port of the test        (default: $PORT)
  DURATION      default transfer duration   (default: $DURATION)
  REPEAT        default number of runs      (default: $REPEAT)
  LOSS_RATE     default loss percentage     (default: $LOSS_RATE)
  LOSS_DELAY    default delay in ms         (default: $LOSS_DELAY)
  LOSS_MODE     per-ip or shared            (default: $LOSS_MODE)
  LOSS_PORTS    number of netem instances   (default: $LOSS_PORTS)
  LOADER_PATH   BPF loader inside the client(default: $LOADER_PATH)
EOF
}

need_docker() {
    command -v docker >/dev/null 2>&1 || die "docker is not installed"
    docker info >/dev/null 2>&1 || die "cannot talk to the docker daemon"
}

guard_name() {
    # $1: name that we are about to create/remove
    for reserved in $RESERVED_NAMES; do
        if [ "$1" = "$reserved" ]; then
            die "refusing to touch '$1': that name belongs to another workstream"
        fi
    done
}

container_exists() {
    docker inspect --type container "$1" >/dev/null 2>&1
}

container_running() {
    [ "$(docker inspect --type container -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)" = "true" ]
}

network_exists() {
    docker network inspect "$1" >/dev/null 2>&1
}

image_exists() {
    docker image inspect "$1" >/dev/null 2>&1
}

v6_prefix_len() {
    printf '%s\n' "${V6_SUBNET#*/}"
}

# The container image needs iproute2 for "tc" and netem.
ensure_lab_image() {
    if image_exists "$LAB_IMAGE"; then
        return 0
    fi
    log "building lab image $LAB_IMAGE (adds iproute2)"
    docker build -t "$LAB_IMAGE" - <<EOF
FROM $BENCH_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
EOF
}

# The build image needs a C compiler.
ensure_build_image() {
    if image_exists "$BUILD_IMAGE"; then
        return 0
    fi
    log "building build image $BUILD_IMAGE (adds gcc/make)"
    docker build -t "$BUILD_IMAGE" - <<EOF
FROM $BENCH_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev make \
    && rm -rf /var/lib/apt/lists/*
EOF
}

# The directory holding the congestion-control sources; it is mounted into the
# client container so that the loader and its BPF object are reachable.
cc_src_dir() {
    printf '%s' "$CC_SRC_DIR"
}

bench_dir() {
    printf '%s\n' "$(cd "$(dirname "$0")" && pwd)"
}

# ====================================================================
# up / down / status
# ====================================================================

cmd_up() {
    need_docker
    guard_name "$BENCH_NET"
    guard_name "$CLIENT_NAME"
    guard_name "$SERVER_NAME"

    ensure_lab_image

    if network_exists "$BENCH_NET"; then
        log "network $BENCH_NET already exists"
    else
        log "creating network $BENCH_NET ($V4_SUBNET, $V6_SUBNET)"
        docker network create --ipv6 \
            --subnet "$V4_SUBNET" \
            --subnet "$V6_SUBNET" \
            "$BENCH_NET" >/dev/null
    fi

    if container_exists "$CLIENT_NAME"; then
        log "container $CLIENT_NAME already exists"
        if ! container_running "$CLIENT_NAME"; then
            log "starting $CLIENT_NAME"
            docker start "$CLIENT_NAME" >/dev/null
        fi
    else
        log "creating client container $CLIENT_NAME ($CLIENT_V6)"
        docker run -d \
            --name "$CLIENT_NAME" \
            --hostname "$CLIENT_NAME" \
            --network "$BENCH_NET" \
            --ip6 "$CLIENT_V6" \
            --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add BPF \
            --security-opt apparmor=unconfined \
            -v "$(bench_dir):/lab" \
            -v "$(cc_src_dir):/cc:ro" \
            "$LAB_IMAGE" sleep infinity >/dev/null
    fi

    if container_exists "$SERVER_NAME"; then
        log "container $SERVER_NAME already exists"
        if ! container_running "$SERVER_NAME"; then
            log "starting $SERVER_NAME"
            docker start "$SERVER_NAME" >/dev/null
        fi
    else
        log "creating server container $SERVER_NAME ($SERVER_V6)"
        docker run -d \
            --name "$SERVER_NAME" \
            --hostname "$SERVER_NAME" \
            --network "$BENCH_NET" \
            --ip6 "$SERVER_V6" \
            --cap-add NET_ADMIN --cap-add SYS_ADMIN \
            --security-opt apparmor=unconfined \
            -v "$(bench_dir):/lab" \
            "$LAB_IMAGE" sleep infinity >/dev/null
    fi

    cmd_status
}

cmd_down() {
    need_docker
    guard_name "$CLIENT_NAME"
    guard_name "$SERVER_NAME"
    guard_name "$BENCH_NET"

    if container_exists "$CLIENT_NAME"; then
        log "removing container $CLIENT_NAME"
        docker rm -f "$CLIENT_NAME" >/dev/null
    fi
    if container_exists "$SERVER_NAME"; then
        log "removing container $SERVER_NAME"
        docker rm -f "$SERVER_NAME" >/dev/null
    fi
    if network_exists "$BENCH_NET"; then
        log "removing network $BENCH_NET"
        docker network rm "$BENCH_NET" >/dev/null
    fi
    if [ "${PURGE_IMAGES:-0}" = "1" ]; then
        log "removing images $LAB_IMAGE $BUILD_IMAGE"
        docker image rm -f "$LAB_IMAGE" >/dev/null 2>&1 || true
        docker image rm -f "$BUILD_IMAGE" >/dev/null 2>&1 || true
    fi
    log "done"
}

cmd_status() {
    need_docker

    printf 'network %-16s : %s\n' "$BENCH_NET" \
        "$(network_exists "$BENCH_NET" && echo present || echo missing)"
    printf 'container %-12s : %s\n' "$CLIENT_NAME" \
        "$(container_exists "$CLIENT_NAME" && echo present || echo missing)"
    printf 'container %-12s : %s\n' "$SERVER_NAME" \
        "$(container_exists "$SERVER_NAME" && echo present || echo missing)"
    printf 'image %-19s : %s\n' "$LAB_IMAGE" \
        "$(image_exists "$LAB_IMAGE" && echo present || echo missing)"
    printf 'tool /lab/tcperf   : %s\n' \
        "$([ -x "$(bench_dir)/tcperf" ] && echo built || echo missing)"

    if container_running "$CLIENT_NAME"; then
        printf '\nclient addresses:\n'
        docker exec "$CLIENT_NAME" ip -6 addr show dev "$CLIENT_IF" 2>/dev/null || true
        printf '\ncongestion control available in the client netns:\n'
        docker exec "$CLIENT_NAME" cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || true
        printf '\nqdisc configuration on %s:\n' "$CLIENT_IF"
        docker exec "$CLIENT_NAME" tc -s qdisc show dev "$CLIENT_IF" 2>/dev/null || true
        if docker exec "$CLIENT_NAME" test -x "$LOADER_PATH" 2>/dev/null; then
            printf '\nBPF loader: %s present\n' "$LOADER_PATH"
        else
            printf '\nBPF loader: %s MISSING (lab.sh loadcc will not work)\n' "$LOADER_PATH"
        fi
    fi
}

# ====================================================================
# build
# ====================================================================

cmd_build() {
    need_docker
    ensure_build_image
    log "building tcperf in $BUILD_IMAGE"
    docker run --rm \
        -v "$(bench_dir):/lab" \
        -w /lab \
        "$BUILD_IMAGE" make "$@"
}

# ====================================================================
# loss: shape the client -> server path
# ====================================================================

# client_ipv6_for <n> -> the n-th (1 based) client source address
client_ipv6_for() {
    printf '%s:%x\n' "${CLIENT_V6%:*}" "$(( $(printf '%d' "0x${CLIENT_V6##*:}") + $1 - 1 ))"
}

cmd_loss() {
    need_docker
    rate="$LOSS_RATE"
    delay_ms="$LOSS_DELAY"
    mode="$LOSS_MODE"
    ports="$LOSS_PORTS"

    while [ $# -gt 0 ]; do
        case "$1" in
            --rate)
                [ $# -ge 2 ] || die "--rate requires an argument"
                rate="$2"
                shift 2
                ;;
            --rate=*)
                rate="${1#--rate=}"
                shift
                ;;
            --delay)
                [ $# -ge 2 ] || die "--delay requires an argument"
                delay_ms="$2"
                shift 2
                ;;
            --delay=*)
                delay_ms="${1#--delay=}"
                shift
                ;;
            --mode)
                [ $# -ge 2 ] || die "--mode requires an argument"
                mode="$2"
                shift 2
                ;;
            --mode=*)
                mode="${1#--mode=}"
                shift
                ;;
            --ports)
                [ $# -ge 2 ] || die "--ports requires an argument"
                ports="$2"
                shift 2
                ;;
            --ports=*)
                ports="${1#--ports=}"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown option '$1' for 'loss'"
                ;;
        esac
    done

    [ "$mode" = "per-ip" ] || [ "$mode" = "shared" ] \
        || die "--mode must be per-ip or shared"
    [ "$ports" -ge 1 ] 2>/dev/null || die "--ports must be a number >= 1"
    container_running "$CLIENT_NAME" \
        || die "client container $CLIENT_NAME is not running (run 'lab.sh up' first)"

    log "clearing existing qdisc on $CLIENT_IF"
    docker exec "$CLIENT_NAME" tc qdisc del dev "$CLIENT_IF" root >/dev/null 2>&1 || true

    if [ "$mode" = "shared" ]; then
        log "shared netem: loss ${rate}% delay ${delay_ms}ms on the root qdisc"
        docker exec "$CLIENT_NAME" tc qdisc add dev "$CLIENT_IF" root handle 1: \
            netem delay "${delay_ms}ms" loss "${rate}%"
        log "current qdisc configuration:"
        docker exec "$CLIENT_NAME" tc qdisc show dev "$CLIENT_IF" >&2
        return 0
    fi

    # per-ip mode: one independent netem instance per source IPv6 address.
    # A "prio" root qdisc provides one band per address, every band carries
    # its own netem qdisc, and a flower filter steers each source address
    # into its own band.
    #
    # Note: the kernel rejects a prio qdisc with less than three bands
    # (the default priomap sanity check), hence the minimum of three.
    bands=$((ports + 1))
    if [ "$bands" -lt 3 ]; then
        bands=3
    fi

    log "per-ip netem: $ports independent instance(s), loss ${rate}% delay ${delay_ms}ms"

    docker exec "$CLIENT_NAME" tc qdisc add dev "$CLIENT_IF" root handle 1: \
        prio bands "$bands"

    i=1
    while [ "$i" -le "$ports" ]; do
        src="$(client_ipv6_for "$i")"
        band="$i"
        handle=$((10 + i))

        # the extra source addresses have to exist on the interface
        if [ "$i" -gt 1 ]; then
            docker exec "$CLIENT_NAME" ip -6 addr add "$src/$(v6_prefix_len)" \
                dev "$CLIENT_IF" >/dev/null 2>&1 || true
        fi

        docker exec "$CLIENT_NAME" tc qdisc add dev "$CLIENT_IF" parent "1:$band" \
            handle "$handle:" netem delay "${delay_ms}ms" loss "${rate}%"
        docker exec "$CLIENT_NAME" tc filter add dev "$CLIENT_IF" protocol ipv6 \
            parent 1: prio "$band" flower src_ip "$src/128" flowid "1:$band"
        log "  $src -> band $band (handle $handle:)"
        i=$((i + 1))
    done

    log "current qdisc configuration:"
    docker exec "$CLIENT_NAME" tc qdisc show dev "$CLIENT_IF" >&2
    docker exec "$CLIENT_NAME" tc filter show dev "$CLIENT_IF" parent 1: >&2
}

# ====================================================================
# compare
# ====================================================================

# extract "key=value" from a RESULT line
result_field() {
    printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n 1
}

cmd_compare() {
    need_docker
    cclist=""
    duration="$DURATION"
    repeat="$REPEAT"
    skip_missing=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --cc)
                [ $# -ge 2 ] || die "--cc requires an argument"
                cclist="$2"
                shift 2
                ;;
            --cc=*)
                cclist="${1#--cc=}"
                shift
                ;;
            --duration)
                [ $# -ge 2 ] || die "--duration requires an argument"
                duration="$2"
                shift 2
                ;;
            --duration=*)
                duration="${1#--duration=}"
                shift
                ;;
            --repeat)
                [ $# -ge 2 ] || die "--repeat requires an argument"
                repeat="$2"
                shift 2
                ;;
            --repeat=*)
                repeat="${1#--repeat=}"
                shift
                ;;
            --skip-missing)
                skip_missing=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown option '$1' for 'compare'"
                ;;
        esac
    done

    [ -n "$cclist" ] || die "compare requires --cc <a,b,c>"
    container_running "$CLIENT_NAME" \
        || die "client container $CLIENT_NAME is not running (run 'lab.sh up' first)"
    container_running "$SERVER_NAME" \
        || die "server container $SERVER_NAME is not running (run 'lab.sh up' first)"
    [ -x "$(bench_dir)/tcperf" ] \
        || die "tcperf is not built; run 'lab.sh build' or 'make' first"

    available="$(docker exec "$CLIENT_NAME" \
        cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || echo '')"

    tmpd="$(mktemp -d)"
    trap 'rm -rf "$tmpd"' EXIT INT TERM

    rows="$tmpd/rows"

    for cc in $(printf '%s' "$cclist" | tr ',' ' '); do
        if ! printf '%s\n' "$available" | tr ' ' '\n' | grep -qx "$cc"; then
            if [ "$skip_missing" = "1" ]; then
                log "skipping '$cc': not available in the client netns"
                continue
            fi
            die "congestion control '$cc' is not available in the client netns (available: $available)"
        fi

        rep=1
        while [ "$rep" -le "$repeat" ]; do
            log "run $rep/$repeat: cc=$cc duration=${duration}s"

            : > "$tmpd/server.out"
            : > "$tmpd/server.err"
            : > "$tmpd/client.out"
            : > "$tmpd/client.err"

            server_duration=$((duration + 15))

            docker exec "$SERVER_NAME" /lab/tcperf server \
                --bind "$SERVER_V6" --port "$PORT" \
                --duration "$server_duration" --so-rcvbuf "$RCVBUF" \
                > "$tmpd/server.out" 2> "$tmpd/server.err" &
            srv_pid=$!

            # wait until the server is listening
            waited=0
            while [ "$waited" -lt 100 ]; do
                if grep -q "listening on" "$tmpd/server.err" 2>/dev/null; then
                    break
                fi
                sleep 0.1
                waited=$((waited + 1))
            done

            docker exec "$CLIENT_NAME" /lab/tcperf client \
                --dst "$SERVER_V6" --port "$PORT" --cc "$cc" \
                --duration "$duration" --write-size "$WRITE_SIZE" \
                --so-sndbuf "$SNDBUF" --quiet \
                > "$tmpd/client.out" 2> "$tmpd/client.err" || true

            wait "$srv_pid" 2>/dev/null || true

            client_line="$(grep '^RESULT ' "$tmpd/client.out" | head -n 1 || true)"
            server_line="$(grep '^RESULT ' "$tmpd/server.out" | head -n 1 || true)"

            if [ -z "$client_line" ]; then
                log "client produced no RESULT line:"
                sed 's/^/  /' "$tmpd/client.err" >&2 || true
                die "run of cc=$cc failed"
            fi

            # the RESULT lines are machine readable, keep them on stdout
            printf '%s\n' "$client_line"
            if [ -n "$server_line" ]; then
                printf '%s\n' "$server_line"
            fi

            c_bytes="$(result_field "$client_line" bytes)"
            c_elapsed="$(result_field "$client_line" elapsed)"
            c_mbit="$(result_field "$client_line" mbit)"
            c_cwnd="$(result_field "$client_line" cwnd)"
            c_ssthresh="$(result_field "$client_line" ssthresh)"
            c_rtt="$(result_field "$client_line" rtt_us)"
            c_retrans="$(result_field "$client_line" retrans)"
            c_pacing="$(result_field "$client_line" pacing)"
            s_bytes="$(result_field "$server_line" bytes)"

            printf '%s %s %s %s %s %s %s %s %s %s %s\n' \
                "$cc" "$rep" "${c_mbit:-0}" "${c_bytes:-0}" "${c_elapsed:-0}" \
                "${c_cwnd:-}" "${c_ssthresh:-}" "${c_rtt:-}" "${c_retrans:-}" \
                "${c_pacing:-}" "${s_bytes:-}" >> "$rows"

            rep=$((rep + 1))
        done
    done

    printf '\n'
    printf '%-10s %4s %10s %12s %9s %8s %10s %9s %9s %12s %12s\n' \
        cc run Mbit/s bytes elapsed cwnd ssthresh rtt_us retrans pacing srv_bytes
    while read -r cc rep mbit bytes elapsed cwnd ssthresh rtt retrans pacing sbytes; do
        printf '%-10s %4s %10s %12s %9s %8s %10s %9s %9s %12s %12s\n' \
            "$cc" "$rep" "$mbit" "$bytes" "$elapsed" "$cwnd" "$ssthresh" \
            "$rtt" "$retrans" "$pacing" "$sbytes"
    done < "$rows"

    printf '\nsummary\n'
    awk '
        { cc = $1; v = $3 + 0;
          if (!(cc in seen)) { order[++n] = cc; seen[cc] = 1 }
          cnt[cc]++; sum[cc] += v; sumsq[cc] += v * v;
          if (!(cc in mn) || v < mn[cc]) mn[cc] = v;
          if (v > mx[cc]) mx[cc] = v }
        END {
            printf "%-10s %6s %10s %10s %10s\n", "cc", "runs", "mean", "min", "max";
            for (i = 1; i <= n; i++) {
                c = order[i]; mean = sum[c] / cnt[c];
                var = (cnt[c] > 1) ? (sumsq[c] - cnt[c] * mean * mean) / (cnt[c] - 1) : 0;
                if (var < 0) var = 0;
                printf "%-10s %6d %10.2f %10.2f %10.2f  stddev=%.2f\n",
                       c, cnt[c], mean, mn[c], mx[c], sqrt(var);
            }
        }' "$rows"
}

# ====================================================================
# BPF congestion control loader
# ====================================================================

cmd_loadcc() {
    need_docker
    object=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --object)
                [ $# -ge 2 ] || die "--object requires an argument"
                object="$2"
                shift 2
                ;;
            --object=*)
                object="${1#--object=}"
                shift
                ;;
            *)
                die "unknown option '$1' for 'loadcc'"
                ;;
        esac
    done

    [ -n "$object" ] || die "loadcc requires --object <path to the .o file>"
    [ -f "$object" ] || die "object file not found: $object"
    container_running "$CLIENT_NAME" \
        || die "client container $CLIENT_NAME is not running (run 'lab.sh up' first)"

    if ! docker exec "$CLIENT_NAME" test -x "$LOADER_PATH" 2>/dev/null; then
        die "the loader $LOADER_PATH does not exist in $CLIENT_NAME.
       It is expected in the bind mounted bench directory (src/bench/cc/qkctl)
       and must be executable.  Build it first, then retry."
    fi

    log "copying $object into $CLIENT_NAME:$CC_OBJ_DIR"
    docker exec "$CLIENT_NAME" mkdir -p "$CC_OBJ_DIR"
    docker cp "$object" "$CLIENT_NAME:$CC_OBJ_DIR/$(basename "$object")"

    daemon_flag=""
    if [ "$LOADCC_DAEMON" = "1" ]; then
        daemon_flag="--daemon"
    fi

    log "loading the congestion control object in the client netns"
    docker exec "$CLIENT_NAME" "$LOADER_PATH" load \
        --object "$CC_OBJ_DIR/$(basename "$object")" $daemon_flag

    log "congestion control available in the client netns now:"
    docker exec "$CLIENT_NAME" \
        cat /proc/sys/net/ipv4/tcp_available_congestion_control >&2
}

cmd_unloadcc() {
    need_docker
    container_running "$CLIENT_NAME" \
        || die "client container $CLIENT_NAME is not running (run 'lab.sh up' first)"

    if ! docker exec "$CLIENT_NAME" test -x "$LOADER_PATH" 2>/dev/null; then
        die "the loader $LOADER_PATH does not exist in $CLIENT_NAME, cannot unload"
    fi

    log "unloading the congestion control in the client netns"
    docker exec "$CLIENT_NAME" "$LOADER_PATH" unload

    log "congestion control available in the client netns now:"
    docker exec "$CLIENT_NAME" \
        cat /proc/sys/net/ipv4/tcp_available_congestion_control >&2
}

# ====================================================================
# main
# ====================================================================

if [ $# -lt 1 ]; then
    usage
    exit 2
fi

cmd="$1"
shift

case "$cmd" in
    up)       cmd_up "$@" ;;
    down)     cmd_down "$@" ;;
    status)   cmd_status "$@" ;;
    build)    cmd_build "$@" ;;
    loss)     cmd_loss "$@" ;;
    compare)  cmd_compare "$@" ;;
    loadcc)   cmd_loadcc "$@" ;;
    unloadcc) cmd_unloadcc "$@" ;;
    -h|--help|help)
        usage
        exit 0
        ;;
    *)
        printf 'lab: unknown command '\''%s'\''\n' "$cmd" >&2
        usage
        exit 2
        ;;
esac
