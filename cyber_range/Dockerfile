ARG BASE_IMAGE=debian:13.1-slim
FROM ${BASE_IMAGE}

ARG STRONGSWAN_VERSION=6.1.0
ARG STRONGSWAN_SHA256=fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       build-essential ca-certificates curl iproute2 iptables iputils-ping \
       libssl-dev libgmp-dev pkg-config procps tcpdump python3 tini \
    && curl --fail --show-error --location \
       "https://download.strongswan.org/strongswan-${STRONGSWAN_VERSION}.tar.bz2" \
       --output /tmp/strongswan.tar.bz2 \
    && echo "${STRONGSWAN_SHA256}  /tmp/strongswan.tar.bz2" | sha256sum --check - \
    && mkdir /tmp/strongswan-src \
    && tar --extract --bzip2 --file /tmp/strongswan.tar.bz2 --directory /tmp/strongswan-src --strip-components=1 \
    && cd /tmp/strongswan-src \
    && ./configure --prefix=/usr --sysconfdir=/etc \
       --enable-charon --enable-swanctl --enable-vici --enable-kernel-netlink \
       --enable-openssl --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-pubkey \
       --enable-random --enable-nonce --enable-x509 --enable-constraints --enable-revocation \
       --enable-aes --enable-des --enable-md5 --enable-sha1 --enable-sha2 --enable-gcm \
       --enable-curve25519 --enable-chapoly \
    && make -j2 \
    && make install \
    && cd / \
    && rm -rf /tmp/strongswan-src /tmp/strongswan.tar.bz2 \
    && rm -rf /var/lib/apt/lists/*

COPY cyber_range/entrypoint.sh /usr/local/bin/vgx-entrypoint
COPY cyber_range/traffic.py /opt/vgx/traffic.py
COPY cyber_range/traffic_server.py /opt/vgx/traffic_server.py

RUN chmod 0755 /usr/local/bin/vgx-entrypoint /opt/vgx/traffic.py /opt/vgx/traffic_server.py \
    && mkdir -p /run/charon /etc/swanctl/conf.d /scenario

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/vgx-entrypoint"]
CMD ["sleep", "infinity"]
