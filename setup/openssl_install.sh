#!/usr/bin/env bash
set -euo pipefail

OPENSSL_VERSION="3.5.5"
INSTALL_DIR="/opt/openssl-${OPENSSL_VERSION}"
BUILD_DIR="/tmp/openssl-build"
BASE_URL="https://github.com/openssl/openssl/releases/download"

echo "=== Installing OpenSSL ${OPENSSL_VERSION} ==="

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

if [ -f "${INSTALL_DIR}/bin/openssl" ]; then
  echo "OpenSSL ${OPENSSL_VERSION} already installed at ${INSTALL_DIR}"
  "${INSTALL_DIR}/bin/openssl" version
  exit 0
fi

ARCH=$(uname -m)
case $ARCH in
  x86_64)  OPENSSL_TARGET="linux-x86_64" ;;
  aarch64) OPENSSL_TARGET="linux-aarch64" ;;
  *)       OPENSSL_TARGET="linux-generic64" ;;
esac
echo "Architecture: ${ARCH} → ${OPENSSL_TARGET}"

apt-get update -qq
apt-get install -y build-essential zlib1g-dev perl wget gnupg

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

rm -rf "openssl-${OPENSSL_VERSION}" \
       "openssl-${OPENSSL_VERSION}.tar.gz" \
       "openssl-${OPENSSL_VERSION}.tar.gz.asc"

echo "Downloading OpenSSL ${OPENSSL_VERSION}..."
wget -q "${BASE_URL}/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
wget -q "${BASE_URL}/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz.asc"

echo "Verifying GPG signature..."
gpg --keyserver hkps://keys.openpgp.org \
    --recv-keys BA5473A2B0587B07FB27CF2D216094DFD0CB81EF 2>/dev/null || \
gpg --keyserver hkps://keyserver.ubuntu.com \
    --recv-keys BA5473A2B0587B07FB27CF2D216094DFD0CB81EF
gpg --verify "openssl-${OPENSSL_VERSION}.tar.gz.asc" \
             "openssl-${OPENSSL_VERSION}.tar.gz"
echo "GPG verification passed ✓"

tar -xf "openssl-${OPENSSL_VERSION}.tar.gz"
cd "openssl-${OPENSSL_VERSION}"

echo "Configuring..."
./Configure "${OPENSSL_TARGET}" \
  --prefix="${INSTALL_DIR}" \
  --openssldir="${INSTALL_DIR}/ssl" \
  shared \
  '-Wl,-rpath,$(LIBRPATH)'

echo "Compiling..."
make -j"$(nproc)"

echo "Installing..."
make install

if [ -d "${INSTALL_DIR}/lib64" ]; then
  LIB_DIR="${INSTALL_DIR}/lib64"
else
  LIB_DIR="${INSTALL_DIR}/lib"
fi

echo "${LIB_DIR}" > /etc/ld.so.conf.d/openssl-pqc.conf
ldconfig

echo "Verifying..."
"${INSTALL_DIR}/bin/openssl" version -a

"${INSTALL_DIR}/bin/openssl" list -kem-algorithms | grep -i "mlkem" \
  && echo "ML-KEM available ✓" \
  || echo "WARNING: ML-KEM not found"

echo ""
echo "=== Done: ${INSTALL_DIR} ==="
echo "--with-cc-opt=\"-I${INSTALL_DIR}/include\""
echo "--with-ld-opt=\"-L${LIB_DIR} -Wl,-rpath,${LIB_DIR}\""