"""
Measures and compares TLS handshake latency between a classical (X25519)
and a hybrid post-quantum (X25519MLKEM768) HTTPS server.

Each request is made with a fresh TLS connection (no keep-alive) so that
every iteration captures a full handshake. Timing is collected via curl's
built-in -w flag; no external libraries or agents are required.

------------------------------------------------------------------------
METRICS RECORDED
------------------------------------------------------------------------
  tls_handshake_ms  Time from TCP-connected to TLS-complete.
                    Computed as (time_appconnect - time_connect) * 1000.
                    This is the primary metric for comparing classical
                    vs hybrid key exchange overhead.

  ttfb_ms           Time to First Byte. Seconds from request start until
                    the first byte of the response body is received.
                    Includes TCP + TLS + server processing time.

  total_ms          Total request time: from connection start to the last
                    byte of the response body.

  size_bytes        Response body size in bytes. Useful for verifying
                    that the correct endpoint was hit.

------------------------------------------------------------------------
STATISTICAL OUTPUT (printed after each variant/endpoint run)
------------------------------------------------------------------------
  mean      Arithmetic mean across all successful iterations.
  median    Middle value — robust against outliers.
  p95       95th percentile: 95 % of requests were faster than this.
  p99       99th percentile: worst-case tail latency.
  stdev     Standard deviation — spread of the distribution.
  95% CI    95 %% confidence interval for the true mean.
            Computed as mean ± 1.96 * (stdev / sqrt(n)).

  Glass's Δ  Effect size: (mean_hybrid - mean_classic) / stdev_classic.
             Interpretation:
               |Δ| < 0.2  negligible difference
               0.2–0.5    small effect
               0.5–0.8    medium effect
               > 0.8      large effect

------------------------------------------------------------------------
EXAMPLES
------------------------------------------------------------------------
  # Minimal — use built-in defaults (ports 8443/8444, 4 endpoints):
  python curl_benchmark.py --server 203.0.113.1

  # Custom endpoints:
  python curl_benchmark.py --server 203.0.113.1 \\
      --endpoints /health /api/v1/users /download/report.pdf

  # Full config from a JSON file (recommended for reproducibility):
  python curl_benchmark.py --config my_config.json

------------------------------------------------------------------------
CONFIG FILE FORMAT  (all fields optional; defaults shown)
------------------------------------------------------------------------
  {
      "server":     "203.0.113.1",
      "iterations": 200,
      "warmup":     10,
      "endpoints":  ["/api/direct", "/api/payload/1kb"],
      "variants": {
          "classic": {"port": 8443, "curves": "X25519"},
          "hybrid":  {"port": 8444, "curves": "X25519MLKEM768"}
      }
  }

  Fields:
    server      IP address or hostname of the server to benchmark.
    iterations  Number of measured requests per variant/endpoint pair.
                More iterations = narrower confidence interval.
    warmup      Requests made before measurement starts (discarded).
                Eliminates cold-start effects (DNS cache, TCP slow
                start, CPU frequency scaling).
    endpoints   List of URL paths. Each must start with '/'.
    variants    Named TLS configurations. The first entry is treated
                as the control group for Glass's Delta.
                  port    TCP port the server listens on.
                  curves  TLS key-exchange group passed to curl
                          --curves. Must be supported by your curl
                          build (check: curl --version).

------------------------------------------------------------------------
OUTPUT
------------------------------------------------------------------------
  Results are written to:
    results/curl_benchmark/benchmark_<UTC-timestamp>.csv

  CSV columns: variant, endpoint, iteration,
               tls_handshake_ms, ttfb_ms, total_ms, size_bytes

  Each run produces a new timestamped file so multiple runs do not
  overwrite each other. The file is flushed after every
  variant/endpoint block, so partial results are preserved if the
  script is interrupted with Ctrl-C.

------------------------------------------------------------------------
REQUIREMENTS
------------------------------------------------------------------------
  curl built against OpenSSL >= 3.5 (for X25519MLKEM768).
  Python >= 3.10. No third-party packages required.
"""

import argparse
import csv
import datetime
import json
import os
import subprocess
from pathlib import Path
from typing import Optional

import math
import statistics

DEFAULT_SERVER_IP: str = os.environ.get("SERVER_IP", "localhost")
DEFAULT_ITERATIONS: int = 200
DEFAULT_WARMUP: int = 10
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
RESULTS_DIR: Path = Path(
    os.environ.get("RESULTS_DIR", str(PROJECT_ROOT / "results" / "curl_benchmark"))
)

DEFAULT_ENDPOINTS: list[str] = [
    "/api/direct",
    "/api/payload/1kb",
    "/api/payload/100kb",
    "/api/payload/1mb",
]

# variant name -> {port, curves}
DEFAULT_VARIANTS: dict[str, dict] = {
    "classic": {"port": 8443, "curves": "X25519"},
    "hybrid":  {"port": 8444, "curves": "X25519MLKEM768"},
}

CURL_FORMAT: str = ",".join([
    "%{time_connect}",
    "%{time_appconnect}",
    "%{time_starttransfer}",
    "%{time_total}",
    "%{size_download}",
]) + "\n"

CSV_FIELDS: list[str] = [
    "variant", "endpoint", "iteration",
    "tls_handshake_ms", "ttfb_ms", "total_ms", "size_bytes",
]


def load_config(path: str) -> dict:
    """Loads JSON file defined by a user to import configurations for further benchmarking."""  # noqa: E501
    with open(path, encoding="utf-8") as fh:
        import_raw = json.load(fh)

    allowed_attributes = {"server", "iterations", "warmup", "endpoints", "variants"}  # noqa: E501
    denied_attributes = set(import_raw) - allowed_attributes
    if denied_attributes:
        raise ValueError(f"Following JSON attributes are not defined: {denied_attributes}")  # noqa: E501

    if "variants" in import_raw:
        for name, v in import_raw["variants"].items():
            if "port" not in v or "curves" not in v:
                raise ValueError(
                    f"Variant '{name}' must have 'port' and 'curves' keys, not found"  # noqa: E501
                )
    if "endpoints" in import_raw:
        for endpoints in import_raw["endpoints"]:
            if not endpoints.startswith("/"):
                raise ValueError(f"Endpoint error, must start with '/': {endpoints!r}")  # noqa: E501

    return import_raw


def probe_endpoint(url: str, curves: str, timeout: int = 10) -> int:
    """Return HTTP status code for one request, or 0 on connection error."""
    try:
        result = subprocess.run(
            [
                "curl",
                "-w", "%{http_code}",
                "-k", "-s", "-o", "/dev/null",
                "--no-keepalive",
                "--http1.1",
                "--curves", curves,
                "--max-time", str(timeout),
                url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
            check=False,  # we handle errors via returncode below
        )
    except subprocess.TimeoutExpired:
        return 0

    raw = result.stdout.strip()
    try:
        return int(raw)
    except ValueError:
        return 0


def preflight_check(
    server: str,
    endpoints: list[str],
    variants: dict[str, tuple[int, str]],
) -> None:
    """
    Checks if each of endpoints exist on server side, if server returns
    status code not equal to allowed_status_codes, return 1 and stop benchmark.
    """
    print("\n---Checking if endpoints exist---")
    failures: list[str] = []
    allowed_status_codes = {200, 201, 204}

    for endpoint in endpoints:
        for variant, (port, curves) in variants.items():
            url = f"https://{server}:{port}{endpoint}"
            code = probe_endpoint(url, curves)
            status = "OK" if code in allowed_status_codes else "FAIL"
            label = code or "no response"
            print(f"  [{status}] {variant:<10} {url}  →  HTTP {label}")
            if code not in allowed_status_codes:
                failures.append(
                    f"  {variant} {url} returned HTTP {label}"
                )

    if failures:
        print("\nCheck failed — fix the following before benchmarking:")
        for msg in failures:
            print(msg)
        raise SystemExit(1)

    print("All endpoints can be reached — starting benchmark.\n")


def measure_single(url: str, curves: str, timeout: int = 15) -> Optional[dict]:
    """Run one curl request and return timing metrics, or None on error."""
    try:
        result = subprocess.run(
            [
                "curl",
                "-w", CURL_FORMAT,
                "-k", "-s", "-o", "/dev/null",
                "--no-keepalive",
                "--http1.1",
                "--curves", curves,
                "--max-time", str(timeout),
                url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None

    raw = result.stdout.strip()
    if not raw or result.returncode != 0:
        return None

    parts = raw.split(",")
    if len(parts) != 5:
        return None

    try:
        tcp = float(parts[0])
        appconnect = float(parts[1])
        ttfb = float(parts[2])
        total = float(parts[3])
        size = int(float(parts[4]))
    except ValueError:
        return None

    if appconnect == 0:
        return None

    return {
        "tls_handshake_ms": (appconnect - tcp) * 1000,
        "ttfb_ms":          ttfb * 1000,
        "total_ms":         total * 1000,
        "size_bytes":       size,
    }


def percentile(data: list[float], p: float) -> float:
    """Nearest-rank percentile."""
    if not data:
        return float("nan")
    sorted_data = sorted(data)
    k = math.ceil(p / 100 * len(sorted_data)) - 1
    return sorted_data[max(k, 0)]


def confidence_interval_95(data: list[float]) -> tuple[float, float]:
    """95 % CI using t-distribution (two-sided)."""
    n = len(data)
    if n < 2:
        return (float("nan"), float("nan"))
    mean = statistics.mean(data)
    se = statistics.stdev(data) / math.sqrt(n)
    # t critical value for large n ~ 1.96; acceptable for n >= 30
    margin = 1.96 * se
    return (mean - margin, mean + margin)


def glasses_delta(group_a: list[float], group_b: list[float]) -> float:
    """Glass's Delta: (mean_b - mean_a) / stdev_a  (a = control = classic)."""
    if len(group_a) < 2:
        return float("nan")
    return (
        (statistics.mean(group_b) - statistics.mean(group_a))
        / statistics.stdev(group_a)
    )


def summarise(label: str, data: list[float]) -> None:
    """Print mean, median, p95, p99, stdev, and 95% CI for a metric."""
    if not data:
        print(f"  {label}: no data")
        return
    ci_lo, ci_hi = confidence_interval_95(data)
    print(
        f"  {label}: "
        f"mean={statistics.mean(data):.3f}  "
        f"median={statistics.median(data):.3f}  "
        f"p95={percentile(data, 95):.3f}  "
        f"p99={percentile(data, 99):.3f}  "
        f"stdev={statistics.stdev(data):.3f}  "
        f"95%CI=[{ci_lo:.3f}, {ci_hi:.3f}]"
    )


def run_benchmark(writer: csv.DictWriter,
                  variant: str,
                  url: str,
                  curves: str,
                  iterations: int,
                  warmup: int,
                  ) -> list[dict]:
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    """Run warmup + measurement, write each row to CSV immediately."""
    print(f"\n[{variant}] {url}  (curves={curves})")

    print(f"  warmup ({warmup})...", end=" ", flush=True)
    for _ in range(warmup):
        measure_single(url, curves)
    print("done")

    results: list[dict] = []
    errors = 0
    print(f"  measuring ({iterations})...")

    for i in range(1, iterations + 1):
        m = measure_single(url, curves)
        if m is None:
            errors += 1
            continue

        row = {
            "variant":          variant,
            "endpoint":         url.split("//", 1)[-1].split("/", 1)[-1],
            "iteration":        i,
            "tls_handshake_ms": round(m["tls_handshake_ms"], 4),
            "ttfb_ms":          round(m["ttfb_ms"], 4),
            "total_ms":         round(m["total_ms"], 4),
            "size_bytes":       m["size_bytes"],
        }
        writer.writerow(row)
        results.append(m)

        if i % 100 == 0:
            print(f"    {i}/{iterations} done  (errors so far: {errors})")

    if errors:
        print(f"  WARNING: {errors} failed requests were skipped")

    if results:
        summarise("tls_handshake_ms", [r["tls_handshake_ms"] for r in results])
        summarise("ttfb_ms", [r["ttfb_ms"] for r in results])
        summarise("total_ms", [r["total_ms"] for r in results])

    return results


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Hybrid PQC benchmark — compares classical vs hybrid handshake latency"  # noqa: E501
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--config", metavar="FILE",
        help="JSON config file (overrides all other flags)",
    )
    parser.add_argument(
        "--server", default=DEFAULT_SERVER_IP,
        help="Server IP or hostname (default: $SERVER_IP or localhost)",
    )
    parser.add_argument(
        "--iterations", type=int, default=DEFAULT_ITERATIONS,
        help=f"Requests per variant/endpoint (default: {DEFAULT_ITERATIONS})",
    )
    parser.add_argument(
        "--warmup", type=int, default=DEFAULT_WARMUP,
        help=f"Discarded warm-up requests per run (default: {DEFAULT_WARMUP})",
    )
    parser.add_argument(
        "--endpoints", nargs="+", metavar="PATH",
        help=(
            "One or more URL paths to benchmark, e.g. /api/direct."
            f"Default: {DEFAULT_ENDPOINTS}"
        ),
    )
    return parser.parse_args()


def main() -> None:  # pylint: disable=too-many-locals
    """Entry point: resolve config, run preflight, execute benchmark."""
    args = parse_args()

    # --- resolve final config: file > CLI > defaults ---
    config: dict = {}
    if args.config:
        config = load_config(args.config)
        print(f"Config:     {args.config}")

    server = config.get("server", args.server)
    iterations = config.get("iterations", args.iterations)
    warmup = config.get("warmup", args.warmup)
    endpoints = config.get("endpoints", args.endpoints or DEFAULT_ENDPOINTS)
    variants = config.get("variants", DEFAULT_VARIANTS)

    # normalise variants to uniform dict shape
    norm_variants: dict[str, tuple[int, str]] = {
        name: (v["port"], v["curves"]) for name, v in variants.items()
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    csv_path = RESULTS_DIR / f"benchmark_{timestamp}.csv"

    print(f"Server: {server}")
    print(f"Iterations: {iterations}  Warmup: {warmup}")
    print(f"Endpoints: {endpoints}")
    variant_summary = {
        n: f"port={p} curves={c}" for n, (p, c) in norm_variants.items()
    }
    print(f"Variants: {variant_summary}")
    print(f"Output: {csv_path}")

    preflight_check(server, endpoints, norm_variants)

    # control variant is the first one listed (classic by default)
    control_name = next(iter(norm_variants))
    hs_samples: dict[str, dict[str, list[float]]] = {
        name: {} for name in norm_variants
    }

    with csv_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        fh.flush()

        for endpoint in endpoints:
            for variant, (port, curves) in norm_variants.items():
                url = f"https://{server}:{port}{endpoint}"
                results = run_benchmark(
                    writer,
                    variant=variant,
                    url=url,
                    curves=curves,
                    iterations=iterations,
                    warmup=warmup,
                )
                fh.flush()  # safe to Ctrl-C mid-run
                if results:
                    hs_samples[variant][endpoint] = [
                        r["tls_handshake_ms"] for r in results
                    ]

    # Glass's Delta: each non-control variant vs control
    print(
        f"\n--- Glass's Delta (tls_handshake_ms, control={control_name!r}) ---"
    )
    control_hs = hs_samples[control_name]
    for name, samples in hs_samples.items():
        if name == control_name:
            continue
        print(f"  [{control_name}] vs [{name}]")
        for endpoint in endpoints:
            if endpoint in control_hs and endpoint in samples:
                delta = glasses_delta(control_hs[endpoint], samples[endpoint])
                print(f"    {endpoint:<30} Δ = {delta:+.3f}")

    print(f"\nResults written to {csv_path}")


if __name__ == "__main__":
    main()
