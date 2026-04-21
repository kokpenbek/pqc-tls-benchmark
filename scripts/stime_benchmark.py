"""
Measures TLS handshake throughput using openssl s_time.
Runs multiple iterations per variant and saves results to CSV.

CSV columns:
  variant        — "classic" or "hybrid"
  run            — iteration number (1-based)
  connections    — total connections completed
  duration_sec   — measurement window in seconds
  conn_per_sec   — throughput (connections / duration)

Example:
    python3 stime_benchmark.py --server 203.0.113.1 --runs 5
"""

import argparse
import csv
import datetime
import os
import re
import subprocess
import time
from pathlib import Path

DEFAULT_RUNS = 5
DEFAULT_DURATION = 30
OPENSSL_BIN = os.environ.get("OPENSSL_BIN", "openssl")

RESULTS_DIR = Path(__file__).parent.parent / "results" / "stime"

SERVERS = {
    "classic": {"port": 8443},
    "hybrid":  {"port": 8444},
}

CSV_FIELDS = ["variant", "run", "connections", "duration_sec", "conn_per_sec"]

# regex to parse: "7531 connections in 31 real seconds"
PATTERN = re.compile(r"(\d+) connections in (\d+) real seconds")


def run_stime(server: str, port: int, duration: int) -> tuple[int, int] | None:
    """Run one openssl s_time, return (connections, duration_sec) or None."""
    cmd = [
        OPENSSL_BIN, "s_time",
        "-connect", f"{server}:{port}",
        "-new",
        "-time", str(duration),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration + 30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None

    output = result.stderr + result.stdout

    # find the line with "real seconds"
    for line in output.splitlines():
        m = PATTERN.search(line)
        if m and "real" in line:
            return int(m.group(1)), int(m.group(2))

    return None


def main():
    parser = argparse.ArgumentParser(description="openssl s_time benchmark")
    parser.add_argument("--server", default="localhost")
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION)
    parser.add_argument("--pause", type=int, default=5,
                        help="Seconds between runs")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    csv_path = RESULTS_DIR / f"stime_{timestamp}.csv"

    print(f"Server: {args.server}")
    print(f"Runs:   {args.runs} per variant, {args.duration}s each")
    print(f"Output: {csv_path}\n")

    with csv_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for run in range(1, args.runs + 1):
            for variant, cfg in SERVERS.items():
                print(f"[run {run}/{args.runs}] {variant}...", end=" ", flush=True)

                result = run_stime(
                    server=args.server,
                    port=cfg["port"],
                    duration=args.duration,
                )

                if result is None:
                    print("FAILED")
                    continue

                conns, secs = result
                cps = conns / secs

                writer.writerow({
                    "variant": variant,
                    "run": run,
                    "connections": conns,
                    "duration_sec": secs,
                    "conn_per_sec": round(cps, 2),
                })
                fh.flush()
                print(f"{conns} conn in {secs}s ({cps:.1f} conn/s)")

                time.sleep(args.pause)

    print(f"\nResults written to {csv_path}")


if __name__ == "__main__":
    main()
