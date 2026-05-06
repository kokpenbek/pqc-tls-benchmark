# pqc-tls-benchmark

Practical Migration to Post-Quantum Cryptography: Implementing and Benchmarking Hybrid Cryptographic Schemes.

This repository contains the experimental code, raw measurement data, and analysis notebooks for the bachelor's thesis. It compares classical TLS (`X25519`) against hybrid post-quantum key exchange (`X25519MLKEM768`) in a real client–server setup, measuring handshake time, time-to-first-byte (TTFB), and on-the-wire packet sizes under different network conditions.

## Quickstart

For readers who just want to reproduce the results end-to-end on a clean machine:

1. Check compatibility (NGINX against OpenSSL 3.5)
2. Generate endpoints (each different size for amortization):
    - `bash setup/generate_endpoints.sh`
3. Use configuration settings for NGINX (classic and hybrid):
    - `server/classic.conf`
    - `server/hybrid.conf`
4. Install required dependencies:
    - `pip install -r requirements.txt`  
5. Run the measurement client:
    - `python scripts/curl_benchmark.py --help`
    - `python scripts/stime_benchmark.py --help`
6. In case of layered decomposition use following python script:
    - `python scripts/parse_prcap.py --help`
7. Open the analysis notebook to generate figures:
    - `jupyter notebook analysis.ipynb`

## License

This repository is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for the full license text.

## Academic context

This repository contains the implementation, benchmarking scripts, configuration files, raw measurement data, and analysis notebooks created as part of the bachelor's thesis:

**Practical Migration to Post-Quantum Cryptography: Implementing and Benchmarking Hybrid Cryptographic Schemes**

<img src="https://fit.cvut.cz/static/images/fit-cvut-logo-en.svg" alt="FIT CTU logo" height="200">

This software was developed with the support of the **Faculty of Information Technology, Czech Technical University in Prague**.
For more information, visit [fit.cvut.cz](https://fit.cvut.cz).
