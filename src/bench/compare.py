#!/usr/bin/env python3
"""compare — run the raw TCP probe once per congestion control and tabulate.

The probe is a client, so the peer has to be a listener. For a sender-side
comparison, start one listener per algorithm with srv.py and point this at
each of them.

    # on the sending host
    srv.py --port 9001 --cc cubic &
    srv.py --port 9002 --cc bbr &
    srv.py --port 9003 --cc qk &

    # from the peer
    compare.py --port-map 9001:cubic,9002:bbr,9003:qk --host <host> --repeat 3

Everything is a parameter; nothing about a particular host or network is
baked in.
"""

import argparse
import statistics
import subprocess
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "rawtcp.py")


def run_one(host, port, cc, duration, path, tls):
    cmd = [sys.executable, PROBE, "--host", host, "--port", str(port),
           "--cc", cc, "--duration", str(duration), "--path", path]
    if tls:
        cmd.append("--tls")
    out = subprocess.run(cmd, capture_output=True, text=True)
    for line in out.stdout.splitlines():
        if line.startswith("RESULT "):
            fields = dict(kv.split("=", 1) for kv in line.split()[1:])
            return fields
    sys.stderr.write(out.stderr)
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port-map", required=True,
                    help="comma separated port:algorithm pairs")
    ap.add_argument("--duration", type=float, default=15.0)
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--path", default="/")
    ap.add_argument("--tls", action="store_true")
    args = ap.parse_args()

    pairs = []
    for item in args.port_map.split(","):
        port, _, cc = item.partition(":")
        pairs.append((int(port), cc))

    rows = []
    for port, cc in pairs:
        for i in range(args.repeat):
            r = run_one(args.host, port, cc, args.duration, args.path, args.tls)
            if r is None:
                print("compare: %s on port %d did not produce a result"
                      % (cc, port), file=sys.stderr)
                continue
            rows.append((cc, int(r["bytes"]), float(r["elapsed"]),
                         float(r["mbit"])))

    print("%-10s %-6s %12s %10s %10s" % ("cc", "run", "Mbit/s", "bytes", "elapsed"))
    for cc, b, el, mb in rows:
        print("%-10s %-6d %12.2f %10d %10.2f" % (cc, 0, mb, b, el))

    print()
    print("%-10s %6s %10s %10s %10s %10s"
          % ("cc", "runs", "mean", "min", "max", "stddev"))
    for cc, _, _ in pairs:
        vals = [r[3] for r in rows if r[0] == cc]
        if not vals:
            continue
        print("%-10s %6d %10.2f %10.2f %10.2f %10.2f"
              % (cc, len(vals), statistics.mean(vals), min(vals), max(vals),
                 statistics.pstdev(vals) if len(vals) > 1 else 0.0))


if __name__ == "__main__":
    main()
