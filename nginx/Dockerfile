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
COPY nginx/breakglass.conf /etc/nginx/breakglass.conf
COPY nginx/breakglass/ /etc/nginx/breakglass/
COPY frontend/src/ /usr/share/nginx/html/
