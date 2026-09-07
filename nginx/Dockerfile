# SPDX-FileCopyrightText: 2026 OpenBerat contributors
# SPDX-License-Identifier: GPL-3.0-or-later

# conf.d/ AND frontend/src/ are copied onto nginx:alpine — the build context is
# the repository root so both are reachable (ADR-0020). Configuration is baked
# into the image rather than bind-mounted, so a running system cannot drift.
# The only mount is /etc/nginx/certs: certificates are secrets, never baked.
FROM nginx:1.29-alpine
# upgrade picks up security patches newer than the base image; --no-cache
# leaves no apk cache behind, so no separate clean step is needed.
RUN apk upgrade --no-cache && rm /etc/nginx/conf.d/default.conf
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/conf.d/ /etc/nginx/conf.d/
# The break-glass configuration ships in the same image on purpose: nobody
# should have to build one at 3 a.m. to restore access (ADR-0017). It is inert
# until `docker compose --profile breakglass` runs nginx against it.
# Backgrounds a loop that installs generated application blocks; the stock
# entrypoint runs everything in this directory before exec'ing nginx.
COPY nginx/docker-entrypoint.d/ /docker-entrypoint.d/
RUN chmod +x /docker-entrypoint.d/40-generated-reload.sh
COPY nginx/breakglass.conf /etc/nginx/breakglass.conf
COPY nginx/breakglass/ /etc/nginx/breakglass/
COPY frontend/src/ /usr/share/nginx/html/
