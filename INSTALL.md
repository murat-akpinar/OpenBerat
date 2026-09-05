# INSTALL

> **Draft.** Started in Phase 1 and grows with it (TODO.md); rewritten for v1.
> Steps are in install order — each was executed on the lab host as written.

## Prerequisites

- **A common parent domain** (ADR-0015). Every protected application, the
  portal and Keycloak live at `*.apps.<domain>`. The system does not work
  without it. The examples below use `example.local`.
- **Wildcard DNS** for `*.apps.<domain>` pointing at the nginx host — or
  hosts-file entries in a lab (§2).
- **A wildcard certificate** covering `*.apps.<domain>`. The OIDC redirect and
  the `Secure` session cookie do not work over plain HTTP, so this comes
  first. Which CA issues the production certificate is an open question
  (`docs/06`); the lab uses self-signed (§1). Mind the expiry: when this one
  certificate lapses, every application goes down at once (ADR-0015).
- Docker with Compose v2.

## 1. Certificate

nginx expects `certs/wildcard.crt` and `certs/wildcard.key` in the repository's
`certs/` directory, mounted read-only at `/etc/nginx/certs`. The directory is
gitignored — private keys are never committed and never baked into an image.

Lab, self-signed, 2 years:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 730 \
  -keyout certs/wildcard.key -out certs/wildcard.crt \
  -subj "/CN=*.apps.example.local" \
  -addext "subjectAltName=DNS:*.apps.example.local,DNS:apps.example.local"
```

Browsers warn on a self-signed certificate; either import `wildcard.crt` into
the trust store of the machine you browse from, or click through per visit.
`curl` tests take `-k`.

## 2. Name resolution (lab)

On every machine that talks to the stack — the Docker host itself *and* the
machine whose browser you test from:

```
<nginx-host-ip>  portal.apps.example.local auth.apps.example.local whoami.apps.example.local ws.apps.example.local
```

(On the Docker host, `127.0.0.1` works.)

## 3. Environment

Create `.env` next to `docker-compose.yml` (gitignored). Generate the
passwords — e.g. `openssl rand -base64 24` — do not reuse them anywhere:

```
POSTGRES_PASSWORD=…
KC_ADMIN_USER=admin
KC_ADMIN_PASSWORD=…
AD_DOMAIN=ad.example.local
AD_ADMIN_PASSWORD=…
```

## 4. Start

```sh
docker compose build
docker compose up -d nginx
curl -sk https://portal.apps.example.local/   # serves the portal page
```

> Phase 1 is in progress: only nginx is verified so far. The oauth2-proxy
> configuration, the Keycloak realm import, the LDAP bind account and the
> first login are documented here as their TODO items land.
