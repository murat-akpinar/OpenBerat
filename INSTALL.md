# INSTALL

> **Draft.** Started in Phase 1 and grows with it (TODO.md); rewritten for v1.
> Steps are in install order. §1–§4 have been replayed from a fresh checkout on
> the lab host, as written, by someone who had nothing but this file — three
> things in §1 and §3 were wrong and are fixed (`docs/07`).

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
- **Lab only:** the `samba-ad` container provisions a real AD domain, and that
  writes `security.*` extended attributes. A user namespace refuses them
  whatever capabilities the container is given, so the lab does not come up
  inside an unprivileged LXC — it needs bare metal, a VM, or a privileged
  container (`docs/07`). A production install never starts `samba-ad`, so this
  does not apply there.

The three Active Directory items are the operator's, not this repository's, and
none can be skipped — the same table is in both READMEs.

## 1. Certificate

nginx expects `certs/wildcard.crt` and `certs/wildcard.key` in the repository's
`certs/` directory, mounted read-only at `/etc/nginx/certs`. The directory is
gitignored — private keys are never committed and never baked into an image —
so a fresh clone does not have it yet and `mkdir` is part of the step.

Lab, self-signed, 2 years:

```sh
mkdir -p certs
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
passwords — e.g. `openssl rand -base64 24` — do not reuse them anywhere. Two of
the values are not free-form passwords and carry their own command:

```
# Goes into DATABASE_URL, so it has to survive URL parsing. A base64 password
# containing `/` ends the authority component and the client reports
# `invalid integer value "…" for connection option "port"` — nothing points at
# the password. Hex avoids the question:
#   openssl rand -hex 24
POSTGRES_PASSWORD=…
KC_ADMIN_USER=admin
KC_ADMIN_PASSWORD=…
AD_DOMAIN=example.local
AD_ADMIN_PASSWORD=…
# The OIDC client secret. The committed realm export carries a placeholder;
# this is the real value, injected at import and read by oauth2-proxy.
OPENBERAT_CLIENT_SECRET=…
# oauth2-proxy measures the string it is given, not the bytes it decodes to,
# and only decodes the URL-safe alphabet — plain `openssl rand -base64 32` is
# 44 characters and is refused. `cookie_refresh` (ADR-0006) is what makes the
# check strict at all, so this cannot be relaxed:
#   openssl rand -base64 32 | tr -- '+/' '-_'
OAUTH2_PROXY_COOKIE_SECRET=…
# Lab users only (labuser, labadmin). Gone once AD federation lands.
LAB_USER_PASSWORD=…
```

## 4. Start

```sh
docker compose build
docker compose up -d nginx keycloak redis oauth2-proxy
```

The build compiles the backend in release mode and takes a few minutes the
first time; afterwards it is cached.

`oauth2-proxy` performs OIDC discovery once at startup and exits if Keycloak is
not answering yet, so for the ~25 s Keycloak needs to boot and import the realm
`docker compose ps` shows it `restarting` — that is the `restart:
unless-stopped` policy doing its job, and it settles by itself. A restart loop
that does **not** settle is a configuration error, and
`docker compose logs oauth2-proxy` names it on the first line; a rejected
`OAUTH2_PROXY_COOKIE_SECRET` looks exactly the same from `ps`.

Keycloak imports `keycloak/realm/` at boot. Its H2 database is deliberately
not on a volume, so after changing the export the way to re-import is
`docker compose up -d --force-recreate keycloak` — and any change clicked
together in the admin console is lost the same way, on purpose
(`keycloak/README.md`).

Then browse to `https://portal.apps.example.local/`; you are redirected to
Keycloak, and after logging in as `labuser` you land back on the portal.

## 5. One limitation to know before you expose an application

Revocation is bounded for HTTP requests — an account disabled in AD or removed
from a group loses access within six minutes, and the kill switch cuts it in
seconds ([ADR-0016](docs/adr/0016-n03-revocation-targets.md)). **An already-open
WebSocket or SSE connection is outside that.** It is authorised once, at the
upgrade, and never again; measured in the lab, one carrying steady traffic ran
for another eight minutes after its group was removed, and neither the kill
switch nor an nginx reload touched it (`docs/07`). `proxy_read_timeout` bounds
only *idle* connections.

So: an application whose security depends on access ending promptly should not
be published over a long-lived connection behind this proxy. Nothing in the
configuration changes this — it is what "authorise the request" means when there
is only ever one request.

> Phase 1 is in progress. The certificate, the realm import, the oauth2-proxy
> configuration and the first login are done, written above, and verified by
> replaying them on a clean checkout. Still to come: the LDAP bind account and
> everything downstream of it, which waits on the lab AD (TODO.md Phase 1).
