# INSTALL

> **Draft.** Started in Phase 1 and grows with it (TODO.md); rewritten for v1.
> Steps are in install order. §1–§3 and the start-up in §5 have been replayed
> from a fresh checkout on
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
- **A read-only AD service account** for Keycloak's LDAP bind (§4;
  settings in `docs/03-keycloak-ad.md`).
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

### Renewing it

Every host is served from this one certificate, so its expiry takes the whole
system down at once. Renewal does not need an image build or a restart —
`certs/` is mounted, and nginx is the only thing that has to be told:

```sh
# replace certs/wildcard.crt and certs/wildcard.key, then
docker compose exec nginx nginx -s reload
docker compose restart oauth2-proxy
```

Measured under load (`docs/07`): 400 requests spanning the reload, none of them
failed, and nginx serves the new certificate from the first request after it.
Whether the files are overwritten in place or replaced makes no difference.

The second command is only needed while the certificate is **self-signed**:
`docker-compose.yml` mounts `certs/wildcard.crt` into oauth2-proxy as the CA it
validates the issuer with, and it reads that file once at startup. Skip it and
the proxy keeps checking the new certificate against the old one — existing
sessions carry on working, and every *new* login fails on the token exchange
with `x509: certificate signed by unknown authority`, which is a confusing thing
to be debugging at renewal time. Running it costs under a second and no
signed-in user notices; sessions live in Redis, not in the process.

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
# The second client secret: the backend's own service account, which exists
# only so the kill switch can call Keycloak's logout-all (ADR-0019). A
# different value from the one above — that one lives in oauth2-proxy, and
# sharing it would give oauth2-proxy the right to manage users.
OPENBERAT_BACKEND_SECRET=…
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
# Optional: the AD group that grants /api/admin/*. Leave it out to take the
# default. Whatever it names has to match the group mapper's filter, or the
# management plane is unreachable — §4, "The groups".
ADMIN_GROUP=OpenBerat-Admins
```

## 4. Active Directory

**Lab: skip this section.** `samba-ad/fixture.sh` (§5) builds a directory the
committed realm export already matches. This is for pointing Keycloak at a real
one.

None of it comes from `.env`. `AD_DOMAIN` and `AD_ADMIN_PASSWORD` are read by
the `samba-ad` container alone (`docker-compose.yml`), so changing them does not
move a single DN — the directory's shape lives in the realm export and is
edited there, before Keycloak first starts (§5).

### The bind account

One ordinary user, in no privileged group. AD has no read-only flag: the
account is read-only because it is a member of nothing and because the
provider's Edit Mode is `READ_ONLY` (`docs/03`). The shape to copy is the lab's,
in `samba-ad/fixture.sh`:

```sh
samba-tool user create svc-keycloak "$AD_BIND_PASSWORD" \
  --userou="OU=Service Accounts" --description="Keycloak LDAP bind (read-only)"
samba-tool user setexpiry svc-keycloak --noexpiry
```

The non-expiring password is not laziness. This one credential sits on the path
of every login; when it lapses nobody signs in, including whoever would go and
change it. Its value belongs in `AD_BIND_PASSWORD` and nowhere else: the
committed export carries a `${AD_BIND_PASSWORD}` placeholder that Keycloak
resolves from its own environment at import, so the secret never enters a
version-controlled file (`keycloak/README.md`).

### The groups

One `OpenBerat-<scope>` group per entitlement, plus one for `ADMIN_GROUP`. Both
kinds have to match the group mapper's filter, and that is where the two traps
are:

- **`ADMIN_GROUP` has to be inside the filter.** It defaults to
  `OpenBerat-Admins`, which is, and can be pointed anywhere else for a fixed AD
  naming policy (ADR-0008). Point it at a name the filter excludes and it never
  reaches the claim: `/api/admin/*` then answers 403 to everybody, permanently,
  and no database row and no local Keycloak account can let you back in — in a
  fail-closed system the first admin cannot come from the database. Measured
  (`docs/07`): the account in the real admin group goes from 200 to 403 with
  everyone else, and `/api/me` keeps listing that group while reporting
  `"admin": false` — so the symptom reads as a membership problem. The one
  place the two are named together is `docker compose logs backend | grep
  'admin refused'`. Widen the filter to cover the new name in the same edit, or
  leave the variable alone.
- **Never delete and recreate a prefixed group.** Entitlements match on the name
  (ADR-0008), so a group recreated later under an old name inherits that name's
  entitlements and hands them to everyone in the new group. Renaming is safe; it
  is recreation that re-grants, and nothing in the software can catch it. This
  is a change-control rule on the AD side.

### The four environment-specific values

They are in `keycloak/realm/openberat-realm.json`: three on the `ad ldap`
provider component, one on its `openberat-groups` mapper. Everything else there
— the disabled-account filter, `NO_CACHE`, the `(cn=OpenBerat-*)` group filter,
the group strategy — is verified against the lab directory (`docs/03`,
`docs/07`) and is not yours to adjust.

| Where | Key | Lab value |
|---|---|---|
| provider | `connectionUrl` | `ldaps://dc01.example.local:636` |
| provider | `bindDn` | `CN=svc-keycloak,OU=Service Accounts,DC=example,DC=local` |
| provider | `usersDn` | `OU=Users,DC=example,DC=local` |
| mapper | `groups.dn` | `OU=Groups,DC=example,DC=local` |

LDAPS, not plain LDAP on 389 (`docs/03`). The provider runs with
`useTruststoreSpi=always`, so the certificate the DC presents has to be
trusted: put its issuer as a file under `/opt/keycloak/conf/truststores/`.
Keycloak loads every file in that directory at startup and names them in its
first log lines. Without it the provider cannot connect and every login fails
at once.

## 5. Start

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

## 6. Adding an application

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

## 7. How the application learns who the user is

The proxy decides *whether* a request may pass. These headers tell the
application *who* is passing ([ADR-0021](docs/adr/0021-application-identity-trusted-headers.md)).
Every protected location gets them, rewritten from the verified identity, with
the request-side spellings cleared — a client cannot supply its own.

| Header | Contents |
|---|---|
| `X-Auth-Subject` | Keycloak `sub`: stable and opaque, the one to key data on |
| `X-Auth-Username` | the username the person types |
| `X-Auth-Email` | the address from the directory |
| `X-Auth-Groups` | the group list, comma-joined |
| `X-Auth-Request-Id` | the id that correlates this request with the audit record and the nginx log |

Point the application's own reverse-proxy authentication mode at them. Jenkins,
as it was measured in the lab (`docs/07`) — the plugin is
`reverse-proxy-auth-plugin`, and this runs once from `init.groovy.d`:

```groovy
def realm = new ReverseProxySecurityRealm(
  "X-Auth-Username", "X-Auth-Email", "X-Auth-Username",
  "X-Auth-Groups", ",",                 // the group header and its delimiter
  null, null, null, null, false,
  null, null, null, null, null, null,
  null, (Secret) null, (Integer) 15, true, null, null)
Jenkins.get().setSecurityRealm(realm)

def authz = new FullControlOnceLoggedInAuthorizationStrategy()
authz.setAllowAnonymousRead(false)      // in 2.555.1 this setter, not setDenyAnonymousReadAccess
Jenkins.get().setAuthorizationStrategy(authz)
Jenkins.get().save()
```

### The requirement that comes with it

**The upstream must not be reachable from anywhere except the proxy.** With this
mechanism a header *is* the authentication: measured in the lab, one forged
`X-Auth-Username` sent to an application's own port, with no cookie and no
contact with the proxy, was served as an administrator (`docs/07`). Denying
anonymous access on the application side does not help — the forged request is
not anonymous.

- **Same machine:** do not publish the application's port at all. Put the
  container on the network nginx is on and let nginx reach it by name. This is
  what the compose file does for the sample application, and it is the reason
  `docker compose ps` shows no port for it.
- **Another machine:** allow the proxy's address and nothing else. For a
  published Docker port a host firewall rule has to sit in `DOCKER-USER`, because
  the `INPUT` chain never sees forwarded traffic:

  ```
  iptables -I DOCKER-USER 1 -i <lan-if> -p tcp --dport <port> ! -s <proxy-ip> -j DROP
  ```

Test it rather than assume it, from a third machine:

```
curl -H 'X-Auth-Username: someone' -H 'X-Auth-Groups: OpenBerat-Admins' \
     http://<application-host>:<port>/
```

A dropped or refused connection is the answer you want. A page is a finding.
Repeat it **from the proxy's own address** as well: the same request has to
succeed there, or you have not tested the filter, you have broken the
application. And make the rule survive a reboot — `netfilter-persistent` on
Debian and Ubuntu, `iptables-services` on RHEL — because an upstream that comes
back up unfiltered is the one case nothing in this product can see.

### Two things to know before mapping roles from `X-Auth-Groups`

- **It carries more than AD groups.** oauth2-proxy adds Keycloak's realm and
  client roles with a `role:` prefix, so a user in one AD group arrives with
  seven names (`docs/07`). Match the ones you granted; ignore the rest.
- **It is one comma-joined string**, and the application splits it exactly as
  this product does. A group *named* with a comma in it therefore arrives as two
  groups — which is why the Keycloak group filter in §4 is not optional
  ([ADR-0008](docs/adr/0008-group-identity-name.md)).

## 8. One limitation to know before you expose an application

Revocation is bounded for HTTP requests — an account disabled in AD or removed
from a group loses access within six minutes, and the kill switch cuts it in
seconds ([ADR-0016](docs/adr/0016-n03-revocation-targets.md)). **An already-open
WebSocket or SSE connection is outside that.** It is authorised once, at the
upgrade, and never again; measured in the lab, one carrying steady traffic ran
for another eight minutes after its group was removed, and neither the kill
switch nor an nginx reload touched it (`docs/07`). `proxy_read_timeout` bounds
only *idle* connections — and only bounds them: one was cut at 300 s in the lab,
but the reconnect that follows is authorised against a session that can still be
stale, so even an idle connection sits nearer ten minutes than six.

So: an application whose security depends on access ending promptly should not
be published over a long-lived connection behind this proxy. Nothing in the
configuration changes this — it is what "authorise the request" means when there
is only ever one request.

## 9. Backup and restore

Three things on this host cannot be re-derived, and only one of them is in a
volume:

| What | Where | Why it cannot be rebuilt |
|---|---|---|
| `application`, `entitlement`, `audit_event` | the `pg_data` volume | who may reach what, and the record of who did |
| the wildcard certificate | `certs/` | §1 — and its expiry takes every application down at once |
| the secrets | `.env` | §3 — the cookie secret, the two client secrets, the AD bind password |

Everything else comes back by itself, and backing it up would only preserve
drift. The generated nginx blocks are a pure function of the `application`
table and are rendered again at **every backend start**, not only when an admin
changes a row ([ADR-0011](docs/adr/0011-nginx-config-generation.md)), so the
volume nginx shares is never in a backup. Redis holds sessions and the kill
switch's index — losing it signs everyone in again and nothing else. Keycloak's
realm is imported from `keycloak/realm/`, which is in the repository, and the
users are in AD, not in Keycloak.

So the backup is one command, plus the two files:

```sh
docker compose exec -T postgres pg_dump -U openberat openberat \
  > openberat-$(date +%F).sql
```

`certs/` and `.env` are secrets and belong wherever this installation already
keeps secrets — not beside the dump, which is configuration and audit only.

### Restoring

```sh
docker compose stop backend
docker compose exec -T postgres psql -U openberat -d openberat \
  -c 'drop schema public cascade' -c 'create schema public'
docker compose exec -T postgres psql -U openberat -d openberat -v ON_ERROR_STOP=1 \
  < openberat-2026-09-07.sql
docker compose start backend
```

The backend is stopped first because it writes audit rows and applies
migrations: restoring underneath it means restoring into a schema in use.

**The middle command is not optional, and `pg_dump --clean` will not replace
it.** `audit_event` is partitioned, its default partition inherits the primary
key, and a `--clean` dump tries to drop that constraint on its own — measured,
over a database that already has the schema the restore stops at `cannot drop
inherited constraint "audit_event_default_pkey"` before loading a row. Emptying the schema first is
what makes one procedure work on a database in use and on an empty one alike.
`ON_ERROR_STOP=1` is not decoration either: it is what turned that failure into
a restore that stopped rather than a half-loaded one.

On a host that has nothing left the same commands work, with
`docker compose up -d postgres` in front of them and `docker compose up -d`
after.
Nothing else is done by hand — the migrations are in the dump
(`_sqlx_migrations` is an ordinary table), and the backend republishes the
nginx blocks as it starts, so the applications come back without an admin
touching a row.

Rehearsed on the lab, both ways (`docs/07`): the dump is 0.3 s and 32 KB, an
in-place restore 1.0 s including stopping and starting the backend, and a
restore onto deleted volumes had the application answering **200 again 59 s
after it began** — of which the restore itself is 3 s and the rest is Keycloak
importing its realm.

### Rolling a version back

There is no migration rollback. `backend/migrations/` is applied forward only;
there are no down scripts, and the older binary will not run against the newer
schema — measured, it stops with `migration 2 was previously applied but is
missing in the resolved migrations` rather than serving decisions against a
table it does not know. That refusal is fail-closed doing its job, and it
means:

> **Rolling back a version is restoring the dump taken before the upgrade and
> running the previous image.** Which makes that dump the first step of every
> upgrade, not the last.

What it costs is everything written since: entitlement changes an admin can
redo, and audit rows nobody can. Keep them before you overwrite them —

```sh
docker compose exec -T postgres pg_dump -U openberat -a -t 'audit_event*' \
  openberat > audit-before-rollback.sql
```

The `*` is load-bearing: `audit_event` is partitioned, the rows are in
`audit_event_default`, and `-t audit_event` dumps the parent — measured, a
file with **none** of the rows in it and no warning that it was empty. Keep in
mind, too, that they may not load into the older schema. The audit record is
immutable by rule (`CONTRIBUTING.md`), so a column the newer version added is a
column the older one cannot take. That file is evidence; it is not always a
restore.

> Phase 1 and the phases after it are done and this file follows them: the
> certificate, the realm import, the AD federation, the first login, adding an
> application and integrating one are all written above and were replayed on a
> clean checkout. What is still missing belongs to Phase 6 — the audit
> retention job, monitoring and the release image (`TODO.md`).
