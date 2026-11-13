#!/usr/bin/env python3
"""srv — a plain TCP listener that streams bytes, with a per-connection
congestion control.

This is the sending side. The congestion control shapes the sending window
and the pacing rate, so it is selected here, on the accepted socket, before
any data goes out.

Everything is a parameter. Nothing about a particular host, address or
network is baked in.

    srv.py --port 9000 --cc qk --bytes 500000000
    srv.py --port 9000 --cc cubic --bytes 500000000 --path /blob

One result line is printed per connection:

    RESULT role=server cc=qk sent=500000000 elapsed=10.02 mbit=399.36
"""

import argparse
import socket
import sys
import threading
import time


def select_cc(conn, name):
    if not name or name == "default":
        return
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION,
                        name.encode())
    except OSError as exc:
        print("srv: cannot select congestion control %r: %s" % (name, exc),
              file=sys.stderr, flush=True)


def handle(conn, cc, total, path):
    select_cc(conn, cc)
    header = ("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
              "Content-Type: application/octet-stream\r\n\r\n" % total).encode()
    chunk = b"x" * (1 << 20)
    sent = 0
    start = time.time()
    try:
        conn.sendall(header)
        while sent < total:
            n = conn.send(chunk)
            if n == 0:
                break
            sent += n
    except OSError:
        pass
    elapsed = time.time() - start
    print("RESULT role=server cc=%s sent=%d elapsed=%.2f mbit=%.2f"
          % (cc or "default", sent, elapsed, sent * 8 / elapsed / 1e6),
          flush=True)
    try:
        conn.close()
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cc", default="", help="congestion control to select")
    ap.add_argument("--bytes", type=int, default=500 << 20,
                    help="how much to send per connection")
    ap.add_argument("--path", default="/",
                    help="path the client is expected to request")
    ap.add_argument("--bind", default="0.0.0.0")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(16)
    print("srv: listening port=%d cc=%s" % (args.port, args.cc or "default"),
          flush=True)

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle,
                         args=(conn, args.cc, args.bytes, args.path),
                         daemon=True).start()


if __name__ == "__main__":
    main()
