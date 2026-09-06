# 08 — Break-glass

The system is fail-closed on purpose: no decision means no access
([ADR-0017](adr/0017-fail-closed-availability.md)). The cost of that is written
into this file. If the identity chain breaks — the backend, oauth2-proxy,
Keycloak, Redis or Postgres — **every protected application becomes
unreachable**, and this is how they come back before the chain is repaired.

Break-glass serves the applications with **no authorisation at all**. It is an
incident action, not a fallback, and it has to be switched on by a person. While
it is active, everyone who can reach the network can reach every application
behind the proxy.

## Is this the right thing to pull?

A fail-closed system hides its own failures: a broken backend and a policy that
denies everybody look identical from a browser. Two commands tell them apart.

```sh
docker compose exec backend true 2>/dev/null && echo "backend container is up"
docker compose ps
```

`/readyz` is the one that answers the question. It is on the internal network,
so ask it from a container that is already on `core`:

```sh
docker compose exec nginx wget -qO- http://backend:8081/readyz; echo
```

| What comes back | What it means |
|---|---|
| `200`, empty | The chain is fine. **Do not pull break-glass** — a user who cannot reach an application has a policy problem, and the reason is in the nginx access log as `deny="…"` |
| `unreachable: postgres` | Decisions still work for one cache TTL (30 s), then everything denies with `store_unavailable`. Fix Postgres first; this is usually faster than break-glass |
| `unreachable: redis` | Sessions are gone. Users are logged out and cannot log back in |
| Connection refused / no answer | The backend is down. `auth_request` fails, every protected location answers the unavailable page |

Anything other than the first row, with the applications needed **now**, is what
this file is for.

## Pull it

```sh
cd /path/to/OpenBerat
docker compose stop nginx
docker compose --profile breakglass up -d nginx-breakglass
```

Two things are deliberate. `nginx-breakglass` takes the same `:443`, so the
first command is not optional — and that is the point: the two cannot run at
once, and there is no state in which half the traffic is authorised. And the
configuration ships **inside the same image** as the normal one, so nothing has
to be built or copied at three in the morning; `--profile` is the only reason it
is not already running.

## Check it worked

```sh
curl -sI https://sample.apps.example.local/ | head -1
curl -sI https://sample.apps.example.local/ | grep -i x-openberat-breakglass
```

The second line is how anyone answers "is break-glass still on?" without reading
a compose file over somebody's shoulder. Every request is also logged with a
`BREAKGLASS` prefix, so the window is greppable afterwards:

```sh
docker compose logs nginx-breakglass | grep BREAKGLASS | wc -l
```

## What is unprotected while it is on

- **Every protected application, to everyone who can reach the network.** No
  authentication, no authorisation, no policy.
- **No audit.** `audit_event` records decisions, and no decisions are being
  made. The nginx `BREAKGLASS` log lines are the only record of who reached
  what, and they have no identity in them — there is none to have.
- The portal and the Keycloak host are **not served** at all. Break-glass runs
  on `edge` only and knows nothing about them.
- `X-Auth-*` headers are still stripped from incoming requests. That is not
  belt-and-braces: an upstream that trusts those headers cannot tell the PEP has
  been bypassed, and leaving them alone would turn "no authorisation" into
  "authorisation the client writes for itself".

Time-box it. Write down when it went on.

## Put it back

```sh
docker compose --profile breakglass stop nginx-breakglass
docker compose --profile breakglass rm -f nginx-breakglass
docker compose up -d nginx
docker compose exec nginx wget -qO- http://backend:8081/readyz; echo
```

Then confirm authorisation is being enforced again, rather than assuming it:

```sh
curl -sI https://sample.apps.example.local/ | head -1
curl -sI https://sample.apps.example.local/ | grep -i x-openberat-breakglass   # nothing
```

What that first line says depends on whether the outage is over: `302` into the
login flow if the chain is healthy again, or the unavailable page if it is not.
Either is correct — both mean the request was refused. **A `200` without a
session cookie means break-glass is still running.** That is the only answer
worth reacting to, and it is why the check is "not 200" rather than "302".

## Rehearsal record

ADR-0017 is satisfied by the rehearsal, not by this file existing. Every
rehearsal goes in this table.

| Date | Where | Off → on | On → off | Notes |
|---|---|---|---|---|
| 2026-09-06 | local `docker compose` stack, backend stopped | **2.4 s** | **4.4 s** | Both from typing the first command to the verification passing. Going back is the slower half and always will be: the normal nginx has more to load. See the note below. |

What the first rehearsal found, which is not in the procedure above by accident:

- **`docker compose up -d nginx-breakglass` uses whatever `openberat-nginx`
  image already exists**, and the first attempt silently started a stale one
  from an earlier build — a container that came up, published `:443`, and was
  not listening on it. Nothing in `docker compose ps` says so. This is why both
  services share one `image:` name: if the normal nginx is running, the
  break-glass configuration is in the image it is running, and there is nothing
  separate to have forgotten to build. If you are ever unsure, `docker compose
  exec nginx nginx -T | grep breakglass` before you need it, not during.
- The verification after going back has to be "not 200", not "302" — with the
  chain still broken, a correctly restored nginx answers with the unavailable
  page, and a check that insists on a redirect would read that as failure.
