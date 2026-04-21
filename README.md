# pqc-tls-benchmark

Practical migration to post-quantum cryptography: benchmarking hybrid TLS 1.3 on NGINX with OpenSSL 3.5.

This repository contains the experimental code, raw measurement data, and analysis notebooks for the bachelor's thesis. It compares classical TLS (`X25519`) against hybrid post-quantum key exchange (`X25519MLKEM768`) in a real client–server setup, measuring handshake time, time-to-first-byte (TTFB), and on-the-wire packet sizes under different network conditions.

## Quickstart

For readers who just want to reproduce the results end-to-end on a clean machine:

1. Clone the repo
2. Build OpenSSL 3.5 and NGINX from source (bare metal):
    - `bash setup/openssl_install.sh`
    - `bash setup/nginx_install.sh`
3. Generate endpoints (each different size for amortization):
    - `bash setup/generate_endpoints.sh`
4. Install Python dependencies for the benchmark and notebook:
    - `pip install -r requirements.txt`
5. Use configuration settings for NGINX (classic and hybrid):
    - `server/classic.conf`
    - `server/hybrid.conf`
6. Run the measurement client:
    - `python scripts/curl_benchmark.py --help`
    - `python scripts/stime_benchmark.py --help`
7. Open the analysis notebook to generate figures:
    - `jupyter notebook analysis.ipynb`
