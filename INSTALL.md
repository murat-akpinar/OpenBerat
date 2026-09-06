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
- **`NO_CACHE` on Keycloak's LDAP provider.** Measured (`docs/07`): at
  `DEFAULT` a group removed in AD is still in the claim after a brand-new
  login, and nothing bounds the delay. Like the missing `cookie_refresh`, it
  does not fail — it keeps working on entitlements that no longer track AD
  (ADR-0006).
- **A group filter on Keycloak'''s LDAP group mapper**, matching the
  `OpenBerat-` prefix — e.g. `(&(objectClass=group)(cn=OpenBerat-*))`. This is
  not tidiness. Group names reach the backend joined with commas, so a group
  *named* `Payroll,OpenBerat-Admins` arrives as two names and the second one is
  `ADMIN_GROUP`; the filter is what stops such a name from ever entering the
  claim (ADR-0008, `docs/07`). Without it, anyone who can create a group in AD
  can grant themselves the management plane. Widening it is not undone by
  narrowing it again: the groups it excludes are **imported into Keycloak**
  while it is wide and stay there afterwards, so they have to be deleted by
  hand.
- Docker with Compose v2.
- **Lab only:** the `samba-ad` container provisions a real AD domain, and that
  writes `security.*` extended attributes. A user namespace refuses them
  whatever capabilities the container is given, so the lab does not come up
  inside an unprivileged LXC — it needs bare metal, a VM, or a privileged
  container (`docs/07`). Check the host before starting anything, as root:

  ```sh
  touch /tmp/x && python3 -c "import os; os.setxattr('/tmp/x','security.NTACL',b'\0')"
  ```

  If that raises, provisioning gets as far as a database with no machine
  account and the container restarts forever. A production install never
  starts `samba-ad`, so this does not apply there.

The four Active Directory items are the operator's, not this repository's, and
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
# The password Keycloak binds to AD with. The committed realm export carries a
# placeholder; this is the real value, injected at import.
AD_BIND_PASSWORD=…
# Lab only: the password every user in samba-ad/fixture.sh gets. Keycloak holds
# no local users — labuser and labadmin come from the directory.
LAB_USER_PASSWORD=…
```

## 4. Start

```sh
docker compose build
docker compose up -d nginx keycloak redis oauth2-proxy postgres backend
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

The database schema is not in this list because nobody applies it: the backend
runs `backend/migrations/` itself at startup and **exits** if a migration fails
rather than serving against a schema it has not seen. So a first install needs
no `psql`, and an upgrade needs no migration step — `docker compose up -d`
is the whole of it. If the backend will not stay up,
`docker compose logs backend` says which of the two happened on its last line:
it could not reach Postgres, or a migration would not apply.

**Lab: the directory has to have something in it.** Keycloak holds no local
users — `labuser` and everyone else come from AD through the LDAP provider, so
a lab needs the fixture before anyone can log in:

```sh
docker compose up -d samba-ad
docker compose exec -T -e AD_BIND_PASSWORD -e LAB_USER_PASSWORD \
  samba-ad bash < samba-ad/fixture.sh
```

It creates the OUs, the `svc-keycloak` bind account, the `OpenBerat-` groups
and the lab users, and is safe to re-run (`samba-ad/README.md`). If the DC runs
somewhere other than the compose host — because this host is the unprivileged
LXC the prerequisites warn about — then Keycloak needs to reach it by the name
its LDAPS certificate carries, and to trust that certificate:

```yaml
# docker-compose.override.yml, lab only
services:
  samba-ad:
    profiles: ["off-host"]        # not started here
  keycloak:
    extra_hosts: ["dc01.example.local:<the DC's address>"]
    volumes:
      - ./lab-ad/samba-ca.pem:/opt/keycloak/conf/truststores/samba-ca.pem:ro
```

The CA is the DC's own `/var/lib/samba/private/tls/ca.pem`; Keycloak loads
every file under `conf/truststores` at startup and says so in its first
log lines.

Then browse to `https://portal.apps.example.local/`; you are redirected to
Keycloak, and after logging in as `labuser` you land back on the portal.

## 5. Adding an application

Applications are defined through the admin API, not by editing configuration.
The backend renders an nginx `server` block per application into a volume nginx
shares, and nginx installs it itself — an application defined this way is
reachable within a couple of seconds, and no image is rebuilt (ADR-0011).

Two things it cannot do for you, both of which have to exist **before** the
application will work from a browser:

- **Name resolution** for the new hostname — a DNS record, or a hosts entry as
  in §2.
- **The wildcard certificate** has to cover it. `*.apps.example.local` covers
  `newapp.apps.example.local` and does not cover
  `newapp.internal.example.local`.

If a generated block is ever rejected by `nginx -t`, the previous configuration
stays in effect and the reason is in
`/etc/nginx/conf.d/generated/apps.status` inside the nginx container. Nothing
goes down while you read it.

## 6. One limitation to know before you expose an application

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
