# Benchmark Scripts

Python scripts used to collect the raw measurement data analysed in the thesis. Each script writes CSV files to `results/`
for further analysis in `analysis.ipynb`.

## Scripts

| Script | Purpose | Output |
|--------|---------|--------|
| `curl_benchmark.py` | Per-request TLS handshake and total latency | `results/curl_benchmark/benchmark_<ts>.csv` |
| `stime_benchmark.py` | Sustained TLS handshake throughput | `results/stime/stime_<ts>.csv` |

See the module docstring at the top of each script for full usage,
CLI flags, metric definitions, and configuration options.

## Requirements

- Python 3.10+
- `curl` built against OpenSSL 3.5+ (for `curl_benchmark.py`)
- `openssl` 3.5+
- Server configured with two TLS endpoints:
  - Port 8443 — classical X25519
  - Port 8444 — hybrid X25519MLKEM768
