# Endpoint generation script

Quick script to generate endpoint with different payload sizes for amortisation effect.

1. `/api/direct` - 2 B endpoint for key exchange as primary overhead (directly written in NGINX configurations).
2. `/api/payload/1KB` - 1 KB endpoint for small payload size.
3. `/api/payload/100KB` and `/api/payload/1MB` biggest endpoints for amortisation effect.
