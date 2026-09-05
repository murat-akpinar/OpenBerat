# 0017 — Accepting the single point of failure, with a rehearsed break-glass

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The system is deliberately fail-closed: no decision means no access. The
operational consequence is that if `backend` goes down, every protected
application becomes unreachable — and the same is true of nginx, oauth2-proxy,
Redis, Keycloak and Postgres.

Replacing a VPN with this means putting a single point of failure in front of
every internal application. `docs/02` recorded that answering this was mandatory
for the project to be accepted and could not be deferred. It has been deferred
since.

## Options

| Option | Effect | Cost |
|---|---|---|
| **Accept it, with a rehearsed break-glass** | Honest about the trade; recovery is a documented, tested procedure | Someone must actually rehearse it |
| Fail-open on backend failure | No outage | Abandons the product's only real claim. A crashed PDP would become an access grant |
| Full HA in v1 | No single point of failure | Multi-instance cache, session replication, Postgres HA — a different project |

## Decision

**Accept it.** A security product that fails open is not a security product;
this is the same fail-closed rule the project applies to every ambiguous
authorisation decision (`CONTRIBUTING.md`), applied to the system as a whole.

What makes it acceptable is not a promise of uptime but a **rehearsed
break-glass**: a second nginx configuration shipped in the same image, activated
with `docker compose --profile breakglass`, which bypasses `auth_request` and
serves the protected applications directly while the identity chain is repaired.

The procedure is written down as a runbook in the repository
(`docs/08-breakglass.md`, Phase 3) rather than kept by whoever set the system up:
the moment it is needed is the moment one person's machine is not enough.

It lives inside the image because configuration is baked in and not mounted
(`CONTRIBUTING.md`) — nobody should have to build an image at 3 a.m. to restore access.

## Consequences

- **The break-glass is a Phase 3 exit criterion, and "rehearsed" is part of the
  criterion.** A documented but never-executed procedure does not count;
  everything up to Phase 3 is only usable because this works.
- Activating break-glass **removes authorisation entirely** for as long as it is
  active. It is therefore an incident action with its own consequences: it is
  logged, it is time-boxed, and the applications behind it are exposed to every
  user who can reach them on the network. This is why it is a profile that has
  to be switched on deliberately, and not a fallback that triggers by itself.
- The timeout budget (`/decide` 2 s → oauth2-proxy 1 s → sqlx 500 ms) is failure
  mode design, not tuning: without it a slow backend fills nginx's workers at
  the default 60 seconds and the system stops completely rather than degrading.
- `error_page 500 502 503 504` serves a local static maintenance page. A user
  during an outage sees an explanation, not a bare nginx error.
- `backend` stays **stateless** so that horizontal scaling remains available
  without redesign. Running two instances and adding an nginx health check is
  the first thing to do after the first production deployment (Phase 6), and it
  moves the decision cache to Redis (`docs/05`).
- Postgres being unreachable is a partial, better failure: `/decide` returns 403
  `store_unavailable` and cached decisions keep working for their TTL.
- Break-glass is worthless if the operator cannot log into the machine to run
  it. Access to the Docker host must not depend on this product — which is the
  concrete form of the break-glass account question in `docs/06`.
