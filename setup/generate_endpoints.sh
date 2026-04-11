#!/bin/bash
# generate_endpoints.sh
# Generates test payload files for PQC benchmark endpoints

TARGET_DIR="/var/www/example.com"

echo "Generating payload files in $TARGET_DIR..."

# 1kb, 100kb, 1mb binary payloads
dd if=/dev/urandom bs=1024 count=1    of="$TARGET_DIR/1kb.bin"    status=none
dd if=/dev/urandom bs=1024 count=100  of="$TARGET_DIR/100kb.bin"  status=none
dd if=/dev/urandom bs=1024 count=1024 of="$TARGET_DIR/1mb.bin"    status=none

echo "Verifying file sizes..."
ls -lh "$TARGET_DIR/1kb.bin" "$TARGET_DIR/100kb.bin" "$TARGET_DIR/1mb.bin"

echo "Done."