# queqiao-k

A **kernel-native transport for high-loss, long-RTT paths** — research plus a
prototype, built on top of the ideas in the upstream
[Queqiao](https://github.com/bojieli/queqiao) project.

The question this repository is about: *what can be moved into the kernel?*
Queqiao's control policy — the part that decides how fast to send, and the
part that refuses to mistake erasure for congestion — is a surprisingly good
fit for eBPF's `BPF_PROG_TYPE_STRUCT_OPS` interface, which lets a BPF
program take over TCP's congestion control entirely. The transport layer
itself (framing, FEC, retransmission) is the hard part, and the write-up in
`docs/` says where the line falls.

This is research code, not a product. Nothing here is tuned, hardened or
production ready.

---

## Terms

Short definitions for everything the documents use. Read the documents in
order; anything unfamiliar will be here.

### Protocols and networking

| Term | In one line |
| --- | --- |
| TCP | The kernel's reliable, ordered byte stream. Its congestion control decides how fast it may send. |
| UDP | Connectionless, no delivery guarantee. The carrier for the FEC transport. |
| RTT | Round-trip time: how long a packet takes to go out and come back. |
| BDP | Bandwidth-delay product = bandwidth x RTT: how many bytes fit in one round trip. |
| cwnd | Congestion window: the cap on unacknowledged bytes in flight. |
| PRR | Proportional rate reduction: how the kernel shrinks the window during fast recovery. |
| pacing | Sending at a set rate instead of as fast as the queue allows. |
| four-tuple | Source and destination address and port. It is what pins a TCP connection to one path. |
| NAT / CGNAT | Network address translation, and the carrier-grade version of it. A client behind one can only dial out. |
| FEC | Forward error correction: send extra "repair symbols" so the receiver can fill the gaps without waiting for a retransmission. |
| ARQ | Automatic repeat request: recover loss by retransmitting after feedback. |
| BBR | The kernel's rate-based congestion control; it controls the rate rather than the window. |
| cubic | The kernel's default window-based congestion control. |
| AEAD | Encryption with authentication: confidentiality and integrity together. |

### Kernel and eBPF

| Term | In one line |
| --- | --- |
| BPF / eBPF | Berkeley Packet Filter and its extensions: small programs that run inside the kernel. |
| BTF | The kernel's type description: every struct's fields, types and offsets. |
| CO-RE | Compile once, run everywhere: field accesses are resolved against BTF at load time, so one binary works across kernel versions. |
| struct_ops | The kernel's table of pluggable callbacks. A BPF program fills it and the kernel calls it. |
| congestion control | The TCP stack's rules for how fast to send. |
| reno / cubic / BBR | The three congestion controls Linux ships: reno is the old one, cubic is the default, BBR controls the rate rather than the window. |
| slow start / fast recovery / fast retransmit | The three phases of TCP: the window grows exponentially in slow start, a loss starts fast recovery, and duplicate acknowledgements trigger fast retransmit. |
| socket / setsockopt | A socket is one endpoint of a connection inside the kernel; setsockopt sets an option on it, such as which congestion control it should use. |
| kfunc | A kernel function exported so that BPF programs can call it. |
| netem | The kernel's network emulator: delay, jitter, loss and rate limits. |
| qdisc | Queueing discipline, the kernel's traffic-shaping layer. |
| flower | A classifier that matches on packet fields such as source address. |
| tc | Traffic control: the layer where programs are attached to a network device. |
| XDP | The earliest hook, on the network device driver itself. |
| LRU | Least recently used; one kind of BPF map, which evicts cold entries on its own. |
| ABI | The binary interface: the agreed shape of the functions on either side of a call. |

### Measuring

| Term | In one line |
| --- | --- |
| VPS | A rented remote machine. |
| open-loop probe | A measurement that sets its own send rate instead of waiting for feedback; waiting for feedback measures the reaction of TCP rather than the path. |
| per-socket | Selected on one socket, as opposed to globally for the machine. |

## What's here

```
docs/
  kernel-native-transport.md    the research write-up: what the kernel offers,
                                what was measured, and what the measurements
                                mean for the design
  qk-congestion-control.md      the congestion controller: the design, the
                                measurements against plain TCP, and the ceiling
                                it runs into
  transport/                    (in src) the FEC transport prototype

src/
  cc/                           the BPF congestion controller (BPF_PROG_TYPE_
                                STRUCT_OPS) that implements Queqiao's
                                erasure-aware control law in the kernel
  bench/                        the comparison benchmark: the kernel controller
                                against a plain TCP baseline
  tools/                        measurement and inspection tools (see below)
  transport/                    the FEC transport prototype: the layer the
                                congestion control cannot replace

Makefile                        thin wrapper that delegates to the three
                                subprojects
```

**Where to start.** The two documents under `docs/` are in Chinese and are
written to be read in order; each opens with a glossary of every term it
uses. If you are taking this over, read `kernel-native-transport.md` first
(it explains the problem and what the kernel can do), then
`qk-congestion-control.md` (what was built and measured), then the code.

If you only want the short version, it is in "Measured findings" below.

`src/tools` holds two programs:

| tool | what it does |
| --- | --- |
| `qkbtf` | inspects the running kernel's BTF: find types, dump a struct as a C definition, list a struct's fields, show a function's prototype, report a type's size. It exists because `bpftool` is not installed. |
| `qkprobe` | an open-loop UDP probe: sends numbered datagrams at a fixed rate and measures per-source-address loss and delivery rate. |

`src/transport` holds the FEC transport prototype: it sends the data as
symbols over unreliable datagrams and repairs the erasures with forward error
correction, so a loss does not turn into a stall. It is a prototype for
measuring what such a transport is worth; it has no authentication and no
congestion control of its own.

The upstream Queqiao checkout and the scratch directory are **not** part of
this repository; see `.gitignore`.

---

## How to build

The host that drives this project is macOS, which has neither `linux/bpf.h`
nor libbpf. The tools are therefore built inside a Linux container.

```sh
# build the tools inside a throwaway Linux container
make container
```

The container is `public.ecr.aws/docker/library/ubuntu:24.04` — the public
ECR mirror of the Ubuntu image, because the Docker Hub registry is not
reachable from this network. Inside it, `libbpf-dev` (1.3.0), `gcc`,
`libelf-dev` and `zlib1g-dev` are installed, the tools are built, and the
binaries are copied back into `src/tools/build/`.

The runtime and the image are overridable:

```sh
make -C src/tools container CONTAINER=podman IMAGE=public.ecr.aws/docker/library/ubuntu:24.04
```

On a Linux host (or inside a container that already has libbpf) the plain
build works:

```sh
make -C src/tools            # or: make tools
```

Other targets:

```sh
make help                    # what every target does
make clean                   # remove all build output
make -C src/tools clean
```

The binaries produced by the container build are Linux binaries; they run on
Linux, not on the macOS host.

---

## The tools

### `qkbtf` — kernel BTF inspector

Reads `/sys/kernel/btf/vmlinux`, so its answers always describe the kernel
that is actually running.

```
qkbtf find <pattern>              list kernel types whose name contains <pattern>
qkbtf dump <type-name>            print a C definition (and its dependencies)
qkbtf fields <struct-name> [pat]  print a struct's fields: offset, type, name
qkbtf proto <function-name>       print a kernel function's prototype
qkbtf size <type-name>            print a type's size in bytes
```

Examples:

```sh
qkbtf find bpf_crypto
# id=67381 kind=struct name=bpf_crypto_ctx
# id=67387 kind=func name=bpf_crypto_encrypt
# ...

qkbtf size sock
# sock: size=792 bytes (kind=struct, btf_id=111664)

qkbtf fields sock pacing
# struct sock: 792 bytes, 110 members
# offset=480   bits=0     type=unsigned long    name=sk_pacing_rate
# offset=508   bits=0     type=unsigned int     name=sk_pacing_status
# offset=512   bits=0     type=unsigned long    name=sk_max_pacing_rate

qkbtf proto tcp_cong_avoid_ai
# static void tcp_cong_avoid_ai(struct tcp_sock *tp, unsigned int w, unsigned int acked)
# btf_id=113804 linkage=static args=3
```

`dump` emits the requested type *and everything it refers to*, with the
dependencies defined first, so the result is valid C that can be pasted into
a BPF program as a CO-RE type definition. Anonymous kernel structs get
generated names, and `preserve_access_index` is applied where the compiler
supports it (clang), which is what lets the kernel resolve field offsets by
name at load time.

```sh
qkbtf dump sock > sock.h     # a self contained header
```

### `qkprobe` — open-loop UDP probe

"Open loop" means the sender picks its own rate and never waits for
feedback, so the measurement shows how the path behaves rather than how a
congestion control reacted to it.

```
qkprobe recv --bind <ip> --port <n> [--duration <s>] [--bufbytes <n>]
qkprobe send --src  <ip> --dst <ip> --port <n> [--rate <pps>] [--size <bytes>]
              [--duration <s>] [--seed <n>]
```

`send` binds to `--src` and sends numbered datagrams to `--dst` at `--rate`
for `--duration` seconds over a connected UDP socket. `recv` binds to
`--bind`, counts the datagrams it gets and works out how many sequence
numbers never arrived.

Every datagram starts with a fixed magic and a 32 bit sequence number, so
the receiver can reject foreign traffic and spot holes. The payload body is
filled from a reproducible PRNG (`--seed`), so two runs with the same seed
put the same bytes on the wire.

The machine readable summary goes to stdout, everything else to stderr:

```
RESULT role=send src=fd00::20 packets=60000 bytes=72000000 elapsed=12.00 rate=5000
RESULT role=recv count=58100 bytes=69720000 last_seq=58199 gaps=1900
```

A minimal run between two hosts on the same path:

```sh
# on the receiver
qkprobe recv --bind fd00::10 --port 9000 --duration 30

# on the sender
qkprobe send --src fd00::20 --dst fd00::10 --port 9000 --rate 5000 --size 1200 --duration 30
```

To find out whether the carrier accounts loss per source address, run one
`send` per source address and compare the aggregate: three addresses that
each lose 40 % but deliver three times as much mean the loss is per IP, while
an aggregate that stays flat means the bottleneck is shared.

Addresses, ports, rate, size and duration all come from the command line;
there are no hard coded endpoints, and the defaults are listed in
`qkprobe --help`.

---

## Measured findings

The numbers below are the ones measured in the lab described in
`docs/kernel-native-transport.md` (Linux, arm64, 1 vCPU / 2 GB, loss
injected with `netem` per source IPv6 address). They are reproduced here
only as a summary; the write-up has the method, the caveats and the
details.

**Per-IP loss is real.** With one source address and 40 % injected loss the
path delivered 11.45 Mbit/s. With three source addresses, each with its own
independent 40 % `netem` instance, the same path delivered 32.62 Mbit/s — a
factor of 2.85, with the per-address loss rate unchanged. A clean path
delivered 240 Mbit/s.

**Queqiao's control law runs in the kernel.** A `BPF_PROG_TYPE_STRUCT_OPS`
program implementing the erasure-aware controller was registered with the
kernel; the kernel called it 412 times while it maintained a live delivery
rate estimate, a minimum and a smoothed round-trip time. TCP's available
congestion control list afterwards contained the new algorithm, and any
socket could select it with `setsockopt(TCP_CONGESTION, ...)`.

**Encryption is out of reach for eBPF.** The kernel's AEAD interface exists
in BTF, but calling it from a `tc` or `fentry` program is refused by the
kernel. The crypto layer has to come from the kernel itself (IPsec,
WireGuard, `tls_sw`).

**On a 40 % loss path with 200 ms RTT**, TCP (cubic) delivered 0.063
Mbit/s. FEC over three source addresses delivered 97.4 Mbit/s — about 1546
times as much. Simply sending every symbol twice on two different addresses
delivered 96.2 Mbit/s, and its residual loss matched the predicted p².

**On a real path, the congestion control is not the thing that matters.**
Measured against a VPS over a 235 ms round trip, with 1.9 % loss on the
wire: a raw UDP probe carried **48 Mbit/s**, TCP with cubic carried
**0.07 Mbit/s**, BBR **0.07 Mbit/s**, the controller **0.08 Mbit/s** — and
the FEC transport **12.45 Mbit/s**, about 178 times the TCP figure. On a
path whose round trip is hundreds of milliseconds, a lost segment costs a
full round trip to repair, and no congestion control can change that;
only a transport that repairs without retransmitting can.

**The kernel controller beats plain TCP on a lossy path, and loses badly to
BBR.** `qk`, the erasure-aware controller in `src/cc`, was measured against
cubic on the same 40 % loss / 100 ms RTT path: **0.89 Mbit/s against
0.14 Mbit/s, a factor of 6.4**. On a real VPS with a 238 ms round-trip time
the comparison against cubic (0.49 against 0.37 Mbit/s) flatters it: BBR
reaches **49 Mbit/s** on that same path, and under 40 % injected loss every
TCP congestion control — BBR included — falls to 0.03–0.07 Mbit/s, where an
FEC transport still delivers 97 Mbit/s. The controller as it stands is
window-based, and a window-only controller oscillates on a long path; BBR's
advantage is rate-based control, which needs the kernel to let a congestion
control write the socket's pacing rate. See `docs/qk-congestion-control.md`.

**The transport has to live above IP.** A TCP connection is pinned to a
four-tuple, so the receiver cannot acknowledge each source address
separately and capacity cannot be aggregated across addresses. Duplicating
packets at the IP layer only lowers loss from p to p² = 16 %, and TCP is
still unusable at 16 % loss.

---

## Sanitization

Everything committed here follows these rules:

* **No real hostnames, usernames, home directory paths or machine
  identifiers.** Paths in the documentation and in the code are relative.
* **No real IP addresses.** Only documentation ranges are used: the ULA
  space `fd00::/8`, the documentation prefix `2001:db8::/32` and loopback.
* **No credentials, tokens or URLs to private endpoints.**
* **Every address, port and endpoint is a parameter.** The tools take them
  on the command line; their defaults are documented in `--help` and in the
  source. Nothing is baked in.

The same rules apply to anything added later.

---

## Status

| piece | state |
| --- | --- |
| research write-up | done, `docs/kernel-native-transport.md` |
| congestion-control write-up | done, `docs/qk-congestion-control.md` |
| `qkbtf`, `qkprobe` | done, built and checked against a live kernel |
| `src/cc` congestion controller | works: registered with the kernel on 5.15 and 7.x, 6.4x cubic on a lossy path, but far behind BBR on a long path — a rate-based rewrite is the next step |
| `src/bench` comparison benchmark | works: per-socket controller selection, reproducible lossy lab |

The open question the project is trying to answer is whether a real path
gives the same per-address independence the lab produced: the loss may be
accounted per IP while the *capacity* is still shared, in which case several
addresses buy more erasure channels but no extra bandwidth.
