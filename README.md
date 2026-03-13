# pqc-tls-benchmark
Practical migration to post-quantum cryptography: hybrid TLS benchmarking with OpenSSL 3.5 and NGINX.

Built as part of a bachelor's thesis. Compares classical TLS (X25519) against hybrid post-quantum key exchange (X25519MLKEM768) in a real client-server setup, measuring handshake time, TTFB, and packet sizes across different network conditions.
