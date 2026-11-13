# Deployment

Getting `qk` onto a machine and measuring it.

## Terms used here

| Term | In one line |
| --- | --- |
| BPF / eBPF | Small programs that run inside the kernel. |
| BTF | The kernel's type description: every struct's fields, types and offsets. |
| congestion control | The TCP stack's rules for how fast to send. |
| pacing rate | The rate the kernel sends at, as opposed to sending as fast as the queue allows. |
| sending window | The unacknowledged bytes allowed in flight. |

## What has to be there

| requirement | how to check |
| --- | --- |
| a kernel with the BPF congestion-control interface | `grep -c bpf_tcp_ca /proc/kallsyms` — should not be 0 |
| a kernel BTF | `ls -l /sys/kernel/btf/vmlinux` |
| clang, and libbpf's headers | `clang --version`, `ls /usr/include/bpf` |

The BPF congestion control interface went into the kernel in 5.19 and has been
backported to some 5.15 kernels. It changed shape afterwards: the callback
gained and lost arguments between versions, and the list of fields a
controller may write changed too. `qk` works out the shape of the running
kernel's interface at build time (see `src/cc/qk_abi.c`) and compiles the
matching variant, so the same source works across kernel versions.

## Getting the code there

The repository is the unit of deployment:

```sh
git clone https://github.com/est/qk.git
cd qk
```

If the repository is private, use a token over HTTPS or a deploy key.

## Building

```sh
deploy/remote-bench.sh build
```

That compiles:

- `build/qk.o` — the controller, working through the kernel's `cong_control`
  callback, which lets it own the socket's pacing rate;
- `build/qk_avoid.o` — the same controller working through the
  additive-increase callback, for kernels whose list of writable fields does
  not include the pacing rate;
- `build/qkctl` — the loader.

The build needs clang and libbpf's headers. On Debian and Ubuntu:

```sh
apt-get install -y clang libbpf-dev
```

On a host without them, `make -C src/cc container` builds inside a
container instead.

## Registering it

```sh
deploy/remote-bench.sh load
```

The loader registers the controller with the kernel's TCP stack and prints
what the kernel now offers:

```
available: reno cubic bbr qk
```

A socket then selects it the usual way, without touching the global default:

```c
setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "qk", 3);
```

or, for a whole network namespace:

```sh
sysctl -w net.ipv4.tcp_congestion_control=qk
```

### Two things worth knowing

**The registration is global, and it sticks.** The kernel's list of congestion
control algorithms is not per network namespace: a controller registered in
one namespace is selectable from every namespace. And a name that has been
registered cannot be replaced — the kernel unregisters a controller when the
struct_ops map element is deleted, not when the program is unloaded, so
unloading needs the holder of the registration to delete that element.
`qkctl unload` does exactly that; if the registering process is gone, the
name stays taken until the machine reboots.

**A kernel may refuse the first build.** Some kernels do not let a
congestion control write the socket's pacing rate. The loader tries the
primary object first and falls back to the second one, and says which it
used.

## Measuring

Against a remote endpoint, as the client:

```sh
deploy/remote-bench.sh bench --host <host> --port <port> --cc cubic,bbr,qk \
    --duration 15 --repeat 3
```

Or over the loopback, which needs no remote peer:

```sh
deploy/remote-bench.sh local --cc cubic,bbr,qk --duration 10 --repeat 3
```

Both print the raw result lines and a table with the mean, the minimum, the
maximum and the standard deviation.

For a bulk transfer the interesting side is the **sender**: the congestion
control shapes the sending window and the pacing rate, so the controller
belongs on the machine that sends the data. When the sender is a server, the
controller has to be selected on the accepted socket.

## Cleaning up

```sh
deploy/remote-bench.sh unload
```

This asks the holder of the registration to delete the map element, which
makes the kernel unregister the controller, and removes the pinned maps.
