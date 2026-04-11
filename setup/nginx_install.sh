#!/usr/bin/env bash
set -euo pipefail

NGINX_VERSION="1.28.2"
OPENSSL_VERSION="3.5.5"
OPENSSL_DIR="/opt/openssl-${OPENSSL_VERSION}"
NGINX_INSTALL_DIR="/opt/nginx-pqc"
BUILD_DIR="/tmp/nginx-build"

echo "=== Installing NGINX ${NGINX_VERSION} with PQC support ==="

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

if [ ! -f "${OPENSSL_DIR}/bin/openssl" ]; then
  echo "ERROR: OpenSSL not found at ${OPENSSL_DIR}"
  echo "Run setup/install_openssl.sh first"
  exit 1
fi

INSTALLED_OPENSSL=$("${OPENSSL_DIR}/bin/openssl" version | awk '{print $2}')
echo "Found OpenSSL: ${INSTALLED_OPENSSL} at ${OPENSSL_DIR} ✓"

if [ -d "${OPENSSL_DIR}/lib64" ]; then
  OPENSSL_LIBS="${OPENSSL_DIR}/lib64"
else
  OPENSSL_LIBS="${OPENSSL_DIR}/lib"
fi
echo "OpenSSL libs: ${OPENSSL_LIBS} ✓"

if [ -f "${NGINX_INSTALL_DIR}/sbin/nginx" ]; then
  echo "NGINX already installed at ${NGINX_INSTALL_DIR}"
  echo "Remove ${NGINX_INSTALL_DIR} to reinstall"
  exit 0
fi

echo "Installing build dependencies..."
apt-get update -qq
apt-get install -y \
  build-essential wget gnupg \
  zlib1g-dev libpcre3 libpcre3-dev

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

rm -rf "nginx-${NGINX_VERSION}" \
       "nginx-${NGINX_VERSION}.tar.gz" \
       "nginx-${NGINX_VERSION}.tar.gz.asc"

# --no-check-certificate: workaround for outdated CA in isolated dev VM
# On production servers (DigitalOcean) this flag is not needed
echo "Downloading NGINX ${NGINX_VERSION}..."
wget -q --no-check-certificate "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
wget -q --no-check-certificate "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz.asc"

echo "Verifying GPG signature..."
for KEY in \
  "13C82A63B603576156E30A4EA0EA981B66B0D967" \
  "D6786CE303D9A9022998DC6CC8464D549AF75C0A" \
  "B0F4253373F8F6F510D42178520A9993A1C052F8"; do
  gpg --keyserver hkps://keys.openpgp.org \
      --recv-keys "${KEY}" 2>/dev/null || \
  gpg --keyserver hkps://keyserver.ubuntu.com \
      --recv-keys "${KEY}" 2>/dev/null || true
done

gpg --verify "nginx-${NGINX_VERSION}.tar.gz.asc" \
             "nginx-${NGINX_VERSION}.tar.gz" \
  && echo "GPG verification passed ✓" \
  || echo "WARNING: GPG verification failed — check nginx.org/en/pgp_keys.html"

echo "Extracting..."
tar -xf "nginx-${NGINX_VERSION}.tar.gz"
cd "nginx-${NGINX_VERSION}"

echo "Configuring NGINX build..."
./configure \
  --prefix="${NGINX_INSTALL_DIR}" \
  --conf-path="${NGINX_INSTALL_DIR}/etc/nginx.conf" \
  --http-log-path="/var/log/nginx/access.log" \
  --error-log-path="/var/log/nginx/error.log" \
  --pid-path="/run/nginx-pqc.pid" \
  --lock-path="/var/lock/nginx-pqc.lock" \
  --http-client-body-temp-path="/var/lib/nginx-pqc/body" \
  --http-proxy-temp-path="/var/lib/nginx-pqc/proxy" \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_stub_status_module \
  --with-http_realip_module \
  --with-threads \
  --with-pcre \
  --with-openssl-opt="enable-tls1_3" \
  --with-cc-opt="-I${OPENSSL_DIR}/include -O2" \
  --with-ld-opt="-L${OPENSSL_LIBS} -Wl,-rpath,${OPENSSL_LIBS}"

echo "Compiling NGINX (this takes a few minutes)..."
make -j"$(nproc)"

echo "Installing..."
make install

echo "Creating required directories..."
mkdir -p /var/log/nginx
mkdir -p /var/lib/nginx-pqc/{body,proxy}
mkdir -p "${NGINX_INSTALL_DIR}/etc/conf.d"
mkdir -p /var/www

MIME_TYPES_PATH="${NGINX_INSTALL_DIR}/conf/mime.types"
if [ ! -f "${MIME_TYPES_PATH}" ]; then
  MIME_TYPES_PATH="${NGINX_INSTALL_DIR}/etc/mime.types"
fi

echo "Creating base nginx.conf..."
cat > "${NGINX_INSTALL_DIR}/etc/nginx.conf" << EOF
user www-data;
worker_processes auto;
pid /run/nginx-pqc.pid;

events {
    worker_connections 1024;
}

http {
    include ${MIME_TYPES_PATH};
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;

    include ${NGINX_INSTALL_DIR}/etc/conf.d/*.conf;
}
EOF

echo "Creating systemd service..."
cat > /etc/systemd/system/nginx-pqc.service << EOF
[Unit]
Description=NGINX with PQC support (OpenSSL ${OPENSSL_VERSION})
After=network.target

[Service]
Type=forking
PIDFile=/run/nginx-pqc.pid
ExecStartPre=${NGINX_INSTALL_DIR}/sbin/nginx -t
ExecStart=${NGINX_INSTALL_DIR}/sbin/nginx
ExecReload=${NGINX_INSTALL_DIR}/sbin/nginx -s reload
ExecStop=${NGINX_INSTALL_DIR}/sbin/nginx -s stop
PrivateTmp=true
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo "Verifying NGINX build..."
"${NGINX_INSTALL_DIR}/sbin/nginx" -v 2>&1

echo "Checking OpenSSL linkage..."
ldd "${NGINX_INSTALL_DIR}/sbin/nginx" | grep -i ssl

echo ""
echo "=== NGINX ${NGINX_VERSION} installed successfully ==="
echo "Binary:  ${NGINX_INSTALL_DIR}/sbin/nginx"
echo "Configs: ${NGINX_INSTALL_DIR}/etc/conf.d/"
echo "Logs:    /var/log/nginx/"
echo ""
echo "Next steps:"
echo "  cp server/classic/nginx.conf ${NGINX_INSTALL_DIR}/etc/conf.d/classic.conf"
echo "  cp server/hybrid/nginx.conf  ${NGINX_INSTALL_DIR}/etc/conf.d/hybrid.conf"
echo "  bash server/certs/gen_certs.sh"
echo "  systemctl start nginx-pqc"
echo "  systemctl enable nginx-pqc"