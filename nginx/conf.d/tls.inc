# SPDX-FileCopyrightText: 2026 OpenBerat contributors
# SPDX-License-Identifier: GPL-3.0-or-later

# TLS, set once at http level. One wildcard certificate serves every host
# (ADR-0015), so a copy in each server block is four places to forget — and the
# blocks ADR-0011 generates are written by the backend, which would have to
# carry the path too. Included from nginx.conf and from breakglass.conf: the
# break-glass configuration removes authorisation, not transport security
# (ADR-0017).

# The operator's, mounted read-only at /etc/nginx/certs and never baked into an
# image (INSTALL.md §1). Renewing it is a file swap and a reload, with no
# dropped request and no image build; oauth2-proxy needs restarting too while
# the certificate is self-signed, since it is its own trust anchor then
# (measured, docs/07 — INSTALL.md §1).
ssl_certificate     /etc/nginx/certs/wildcard.crt;
ssl_certificate_key /etc/nginx/certs/wildcard.key;

# Measured on nginx:1.29-alpine: TLS 1.0 and 1.1 are refused *without* this line
# already (docs/07). It is written anyway because the floor belongs to this
# configuration, not to whatever the base image's OpenSSL defaults to next year.
ssl_protocols TLSv1.2 TLSv1.3;

# This one is not decoration. Measured on the stock image, `AES128-SHA` is
# accepted: RSA key exchange, no forward secrecy, so a recorded session becomes
# readable to anyone who later obtains the private key — and what travels on it
# is a session cookie valid for every host on .apps.<domain>. ECDHE with an AEAD
# cipher only. TLS 1.3 has its own suites and ignores this list.
ssl_ciphers EECDH+AESGCM:EECDH+CHACHA20;
