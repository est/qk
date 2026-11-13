#!/usr/bin/env python3
"""udpburst — an open-loop UDP probe that works across NAT.

qkprobe needs a dialable receiver, which rules out measuring the
direction that arrives at a NAT. This probe punches a hole first: the
receiver kicks the sender with a single datagram, and the sender bursts
back at the address that datagram came from.

  # VPS -> Mac (Mac is behind NAT, so the Mac kicks first)
  python3 udpburst.py rx --port 9999 --kick <vps>:9999 --dur 12
  python3 udpburst.py burst --port 9999 --pps 5000 --size 1200 --dur 10

  # Mac -> VPS (the VPS is dialable, no kick needed)
  python3 udpburst.py rx --port 9999 --dur 12
  python3 udpburst.py tx --addr <vps>:9999 --pps 5000 --size 1200 --dur 10

Both ends print one RESULT line; compare sent against received to get
the loss, and bytes against the duration to get the delivered rate.
The receiver anchors its deadline to the first packet so a kick in
flight does not shorten the measurement window.
"""

import argparse
import socket
import struct
import time

HDR = struct.Struct("!QQI")  # seq, send_ts_ms, pad


def now_ms():
    return int(time.time() * 1000)


def parse_addr(s):
    host, _, port = s.rpartition(":")
    if not host or not port.isdigit():
        raise argparse.ArgumentTypeError("expected ip:port, got %r" % s)
    return host, int(port)


def _paced_send(s, dst, pps, size, dur, label):
    """Send at pps for dur seconds, sleeping in small batches.

    Sleep granularity is milliseconds everywhere, so packets due inside
    one granularity step are sent together; the schedule is derived from
    the clock rather than from sleep() calls, so a late sleep does not
    accumulate into a lower rate.
    """
    payload = b"\x00" * max(0, size - HDR.size)
    interval = 1.0 / pps if pps else 0.0
    start = time.monotonic()
    end = start + dur
    sent = 0
    next_t = start
    while True:
        now = time.monotonic()
        if now >= end:
            break
        if now < next_t:
            # sleep, but never past the deadline; batching happens because
            # the loop re-checks the clock and sends everything due
            time.sleep(min(next_t, end) - now)
            continue
        try:
            s.sendto(HDR.pack(sent, now_ms(), 0) + payload, dst)
            sent += 1
        except OSError:
            pass
        next_t += interval
    elapsed = time.monotonic() - start
    print("RESULT role=%s sent=%d dur=%.2f pps=%.0f size=%d mbit=%.2f"
          % (label, sent, elapsed, sent / elapsed if elapsed else 0,
             size, sent * size * 8 / elapsed / 1e6 if elapsed else 0),
          flush=True)
    return sent


def tx(args):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    _paced_send(s, args.addr, args.pps, args.size, args.dur, "tx")


def rx(args):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", args.port))
    if args.kick:
        s.sendto(b"K", args.kick)
        print("rx: kicked %s:%d" % args.kick, flush=True)

    # Wait for the first packet, then run the window from there; the
    # sender's burst may start a one-way delay after the kick.
    s.settimeout(args.wait)
    try:
        first, _ = s.recvfrom(65535)
    except socket.timeout:
        print("RESULT role=rx received=0 bytes=0 note=no_first_packet",
              flush=True)
        return
    s.settimeout(0.5)

    count = 1
    nbytes = len(first)
    first_seq = last_seq = 0
    if len(first) >= HDR.size:
        first_seq = last_seq = HDR.unpack(first[:HDR.size])[0]
    deadline = time.monotonic() + args.dur + 1.0  # 1s grace for the tail
    while time.monotonic() < deadline:
        try:
            data, _ = s.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        count += 1
        nbytes += len(data)
        if len(data) >= HDR.size:
            last_seq = HDR.unpack(data[:HDR.size])[0]
    print("RESULT role=rx received=%d bytes=%d first_seq=%d last_seq=%d "
          "missing=%d"
          % (count, nbytes, first_seq, last_seq,
             (last_seq - first_seq + 1) - count),
          flush=True)


def burst(args):
    """Wait for a kick, then burst back at whoever kicked us."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", args.port))
    s.settimeout(args.wait)
    try:
        _, addr = s.recvfrom(65535)
    except socket.timeout:
        print("RESULT role=burst sent=0 note=no_kick", flush=True)
        return
    print("rx: kick from %s:%d, bursting back" % addr, flush=True)
    _paced_send(s, addr, args.pps, args.size, args.dur, "burst")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="mode", required=True)

    p = sub.add_parser("tx")
    p.add_argument("--addr", type=parse_addr, required=True)
    p.add_argument("--pps", type=int, default=5000)
    p.add_argument("--size", type=int, default=1200)
    p.add_argument("--dur", type=float, default=10.0)

    p = sub.add_parser("rx")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--dur", type=float, default=12.0)
    p.add_argument("--wait", type=float, default=15.0)
    p.add_argument("--kick", type=parse_addr,
                   help="ip:port of the sender to kick first")

    p = sub.add_parser("burst")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--pps", type=int, default=5000)
    p.add_argument("--size", type=int, default=1200)
    p.add_argument("--dur", type=float, default=10.0)
    p.add_argument("--wait", type=float, default=15.0)

    args = ap.parse_args()
    {"tx": tx, "rx": rx, "burst": burst}[args.mode](args)


if __name__ == "__main__":
    main()
