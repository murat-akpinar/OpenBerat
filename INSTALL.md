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
- **Write access to Active Directory** to create the `OpenBerat-` groups.
  Entitlements *are* AD groups; somebody has to be able to make them
  (ADR-0008).
- **A read-only AD service account** for Keycloak's LDAP bind
  (`docs/03-keycloak-ad.md`).
- **One AD group for administrators**, named in `ADMIN_GROUP`. In a fail-closed
  system the first admin cannot come from the database.
- Docker with Compose v2.

The three Active Directory items are the operator's, not this repository's, and
none can be skipped — the same table is in both READMEs.

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
# The OIDC client secret. The committed realm export carries a placeholder;
# this is the real value, injected at import and read by oauth2-proxy.
OPENBERAT_CLIENT_SECRET=…
# Must decode to 16, 24 or 32 bytes — oauth2-proxy refuses to start otherwise:
#   openssl rand -base64 32 | tr -d '\n'
OAUTH2_PROXY_COOKIE_SECRET=…
# Lab users only (labuser, labadmin). Gone once AD federation lands.
LAB_USER_PASSWORD=…
```

## 4. Start

```sh
docker compose build
docker compose up -d nginx keycloak redis oauth2-proxy
```

Keycloak imports `keycloak/realm/` at boot. Its H2 database is deliberately
not on a volume, so after changing the export the way to re-import is
`docker compose up -d --force-recreate keycloak` — and any change clicked
together in the admin console is lost the same way, on purpose
(`keycloak/README.md`).

Then browse to `https://portal.apps.example.local/`; you are redirected to
Keycloak, and after logging in as `labuser` you land back on the portal.

> Phase 1 is in progress. The certificate, the realm import, the oauth2-proxy
> configuration and the first login are done and written above. Still to come:
> the LDAP bind account and everything downstream of it, which waits on the
> lab AD (TODO.md Phase 1).
