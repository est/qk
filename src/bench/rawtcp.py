#!/usr/bin/env python3
"""rawtcp — a raw TCP download probe that selects a congestion control per socket.

The point of this tool is that the congestion control belongs on the
*sender*: it shapes the sending window and the pacing rate. So this is a
client, and the peer has to be a plain listener.

Everything is a parameter. Nothing about a particular host, address or
network is baked in.

    rawtcp.py --host <host> --port <port> --cc cubic --duration 10
    rawtcp.py --host <host> --port <port> --cc bbr --duration 10 --path /file
    rawtcp.py --host <host> --port <port> --cc qk --duration 10 --tls

One result line is printed to stdout, in a stable key=value form, so a
driver can parse it:

    RESULT role=client cc=cubic bytes=12345678 elapsed=10.02 mbit=9.86
"""

import argparse
import errno
import socket
import ssl
import sys
import time

# TCP_CONGESTION is Linux only, and the constant is not exported by every
# version of the socket module. The number is stable in the kernel's
# headers (include/uapi/linux/tcp.h).
TCP_CONGESTION = getattr(socket, "TCP_CONGESTION", 13)
ENOPROTOOPT = getattr(errno, "ENOPROTOOPT", 92)
EINVAL = getattr(errno, "EINVAL", 22)


def select_cc(sock, name):
    """Ask the kernel for a congestion control on this socket.

    This has to happen before the connection is established, or at least
    before any data is sent, because the algorithm is chosen when the
    socket starts sending. A name the kernel does not know is refused
    rather than quietly replaced: a silent fallback would make the whole
    comparison meaningless.
    """
    if not name or name == "default":
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, name.encode())
    except OSError as exc:
        if getattr(exc, "errno", None) in (ENOPROTOOPT, EINVAL) and not sys.platform.startswith("linux"):
            # Not every platform has the option. When the peer selects the
            # algorithm, this side does not need it.
            print("rawtcp: this platform has no TCP_CONGESTION option, "
                  "leaving the choice to the peer", file=sys.stderr)
            return
        raise SystemExit("rawtcp: cannot select congestion control %r: %s"
                         % (name, exc))


def address_family(host):
    """AF_INET6 for a literal IPv6 address, AF_INET otherwise."""
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="peer to connect to")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cc", default="",
                    help="congestion control to select on the socket")
    ap.add_argument("--duration", type=float, default=10.0,
                    help="how long to read for, in seconds")
    ap.add_argument("--path", default="/", help="path to request")
    ap.add_argument("--tls", action="store_true", help="use TLS")
    ap.add_argument("--timeout", type=float, default=15.0,
                    help="connect and read timeout, in seconds")
    args = ap.parse_args()

    sock = socket.socket(address_family(args.host), socket.SOCK_STREAM)
    sock.settimeout(args.timeout)
    select_cc(sock, args.cc)

    try:
        sock.connect((args.host, args.port))
    except OSError as exc:
        raise SystemExit("rawtcp: cannot connect to %s:%d: %s"
                         % (args.host, args.port, exc))

    stream = sock
    if args.tls:
        ctx = ssl.create_default_context()
        stream = ctx.wrap_socket(sock, server_hostname=args.host)

    request = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: rawtcp/1.0\r\n"
               "Accept: */*\r\n\r\n" % (args.path, args.host)).encode()
    try:
        stream.sendall(request)
    except OSError as exc:
        raise SystemExit("rawtcp: cannot send the request: %s" % exc)

    # A short read timeout keeps the loop honest about the deadline: a
    # blocking recv would overrun it by however long the next chunk takes.
    stream.settimeout(1.0)

    total = 0
    start = time.time()
    end = start + args.duration
    while time.time() < end:
        try:
            chunk = stream.recv(1 << 20)
        except socket.timeout:
            continue
        except OSError:
            break
        if not chunk:
            break
        total += len(chunk)
    elapsed = time.time() - start
    try:
        stream.close()
    except OSError:
        pass

    print("RESULT role=client cc=%s bytes=%d elapsed=%.2f mbit=%.2f"
          % (args.cc or "default", total, elapsed, total * 8 / elapsed / 1e6))


if __name__ == "__main__":
    main()
