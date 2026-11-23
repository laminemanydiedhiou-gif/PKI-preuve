# Banc de preuves PKI : OpenSSL + Vault + Certbot + nginx + promtool
FROM hashicorp/vault:1.17 AS vault

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssl python3 python3-cryptography curl jq ca-certificates procps \
      nginx certbot python3-certbot-nginx prometheus \
    && rm -rf /var/lib/apt/lists/*
COPY --from=vault /bin/vault /usr/local/bin/vault
WORKDIR /lab
COPY tests.sh check_certs.py /lab/
ENTRYPOINT ["bash", "/lab/tests.sh"]
