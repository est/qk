# qk — an erasure-aware TCP congestion control for Linux

`qk` is a TCP congestion control algorithm implemented entirely in eBPF. The
kernel's own TCP stack calls it; no userspace process takes part in the
control loop.

The problem it addresses is a path that **erases** packets rather than
congesting them: the loss rate does not depend on the sending rate, so a
conventional loss-based controller backs off for nothing. `qk` treats that
differently:

- the **brake is a delay bound**, not a loss signal — the smoothed round-trip
  time may not exceed a configurable multiple of the path's minimum, and
  beyond that the sending rate is scaled down continuously;
- a **loss does not shrink the window**, because on this path a loss is not
  congestion;
- the measured **erasure rate** is used to size the window and to scale the
  sending rate, so that the rate which *arrives* is the rate that was wanted;
- the compensation is a **bet**: raising it claims that sending more buys
  proportionally more delivery, and the claim is withdrawn when it does not.

The design and the measurements behind it are in
[`docs/qk-congestion-control.md`](../../docs/qk-congestion-control.md).

## Terms used here

| Term | In one line |
| --- | --- |
| BPF / eBPF | Small programs that run inside the kernel. |
| `BPF_PROG_TYPE_STRUCT_OPS` | The BPF program type for filling one of the kernel's pluggable callback tables. |
| congestion control | The TCP stack's rules for how fast to send. |
| pacing rate | The rate the kernel sends at. |
| sending window | The unacknowledged bytes allowed in flight. |
| `setsockopt(TCP_CONGESTION, ...)` | How a socket asks for a particular congestion control, as opposed to setting it for the whole machine. |

## Layout

| file | what it is |
| --- | --- |
| `qk.c` | the BPF program: the congestion-control callbacks and the control law |
| `qk_tunables.h` | the tunable parameters, their defaults, and the map layout — shared with the loader so the defaults exist in exactly one place |
| `qk_state.h` | the per-connection state the controller keeps, shared so the loader can read it back |
| `qkctl.c` | the loader: loads the object, registers the controller, sets tunables, reads the state back |

## Building

The BPF program needs clang's BPF target and Linux uapi headers, which a
macOS host does not have, so the default target builds inside a container:

```sh
make                 # build into build/
make native          # build on a Linux host, without a container
make clean
```

`CONTAINER` and `IMAGE` select the runtime and the base image; the default
image is `public.ecr.aws/docker/library/ubuntu:24.04`.

The name the kernel registers the controller under is compiled in:

```sh
make NAME=qk2       # register as "qk2" instead of "qk"
```

That matters because the kernel's list of congestion control algorithms is
**global**, and a registered name cannot be replaced in place — so testing a
second build alongside a first one needs a second name.

## Using it

```sh
# load and register (stays registered for the lifetime of the kernel)
./build/qkctl load --object build/qk.o

# with tunables
./build/qkctl load --object build/qk.o --set max_comp_ppm=2000000

# keep a handle on it so it can be unloaded again
./build/qkctl load --object build/qk.o --pin-dir /sys/fs/bpf/qk --daemon
./build/qkctl unload --pin-dir /sys/fs/bpf/qk
```

A socket then selects it the usual way, without touching the global default:

```c
setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "qk", 3);
```

or, for a whole network namespace:

```sh
sysctl -w net.ipv4.tcp_congestion_control=qk
```

`qkctl list` prints the algorithms the kernel knows about, and
`qkctl stats` prints what the controller measured for each connection
(needs the state map to be pinned).

## Tunables

All are 32-bit integers, all live in a BPF map, and all can be changed while
the controller is running.

| name | default | meaning |
| --- | ---: | --- |
| `max_comp_ppm` | 4000000 | ceiling on the erasure compensation, in parts per million |
| `comp_step_pct` | 90 | how far the compensation is reduced when a bet fails |
| `bw_decay_pct` | 87 | decay of the delivery-rate maximum filter, per round |
| `brake_ratio_pct` | 200 | the delay bound, as a percentage of the minimum round-trip time |
| `erasure_window` | 2000 | rate samples per round of erasure estimation |
| `floor_decay_pct` | 75 | how fast the erasure floor creeps back up, per round |
| `min_cwnd` | 10 | window floor, in packets |
| `max_cwnd` | 10000 | window ceiling, in packets |
| `mss` | 1460 | assumed segment size, in bytes |
| `bw_pacing` | 0 | 0 = pace from `window * mss / min_rtt`; 1 = pace from the measured delivery rate, with the window held at 2× BDP so it does not bind |

## What the kernel allows

The kernel does not let a congestion control touch the socket freely. The
writable fields are an explicit allowlist (`net/ipv4/bpf_tcp_ca.c`):

```
sock.sk_pacing_rate          sock.sk_pacing_status
icsk_ca_priv                 icsk_ack.pending
tcp_sock.snd_cwnd            tcp_sock.snd_cwnd_cnt
tcp_sock.snd_ssthresh        tcp_sock.ecn_flags        tcp_sock.app_limited
```

Everything else is refused. That is enough for a congestion control, and it
is also the reason the controller cannot repair the loss itself: the kernel's
own recovery machinery — the proportional window reduction during fast
recovery, and the window reset on a retransmission timeout — is performed by
the kernel itself.

Two details of that machinery matter here:

- **The pacing rate is ignored unless the socket is flagged.** The kernel
  only uses `sk_pacing_rate` when `sk_pacing_status` is `SK_PACING_NEEDED`
  (1); a rate written without that flag has no effect and the sender bursts.
  `qk` sets the flag when it initialises the connection, the way BBR does.
- **The timeout window reset is followed by a callback.** `tcp_enter_loss()`
  cuts the window to `packets_in_flight+1` and then calls the `set_state`
  callback, so `qk` restores a sane window there instead of falling into the
  `cwnd=1` death spiral — giving back only the minimum window when the delay
  brake is already engaged. Likewise, the kernel keeps the pre-loss window in
  `prior_cwnd` and hands it back through `undo_cwnd` on an FRTO/DSACK undo.
