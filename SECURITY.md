# Security Policy

OpenBerat sits in front of internal applications and decides who reaches them. A
vulnerability here is a vulnerability in everything behind it. Reports are
welcome and taken seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report privately, by either route:

- GitHub → the repository's **Security → Report a vulnerability** tab (private
  advisory), or
- email **akpinarmurat@protonmail.com**

Please include what someone else needs to reproduce it: the version or commit,
the configuration that matters (nginx location, oauth2-proxy settings,
entitlement rows), and the request that demonstrates the problem. **Redact
secrets** — the client secret, the cookie secret and any real session cookie
reproduce nothing and should not travel in a report.

You will get an acknowledgement within **7 days** and an assessment within
**30 days**. The project is maintained by volunteers; there is no paid support
and no bug bounty.

## Scope

The code is written and installable, so a report can be about a running system
now and not only about the design. **In scope:** the authorisation decision, the
`/decide` contract, header spoofing, the nginx configuration this project
generates, session handling and revocation, the admin API, and the release
bundle. A flaw in the design is still worth reporting on its own — a way around
the decision path in `docs/02-architecture.md`, a rule in
`docs/05-authz-model.md` that does not hold, or a configuration in
`docs/03-keycloak-ad.md` that is unsafe as written.

### Which versions get a fix

One version number covers the whole product
([ADR-0023](docs/adr/0023-versioning-and-release.md)) — the images move
together, so there is no such thing as a fix for the backend alone.

| Version | Supported |
|---|---|
| the newest release | yes |
| anything older | no — upgrade is the fix |
| `main` | yes, and it is where a fix lands first |

Until the first tag exists, report against `main` and name the commit. A
running deployment can name itself: the backend logs its version on its first
line, and `openberat_build_info` on the internal `/metrics` endpoint carries the
same string (`INSTALL.md` §10).

Out of scope: vulnerabilities in Keycloak, oauth2-proxy, nginx, Postgres or
Redis themselves — report those upstream. Findings that depend on a
configuration this project's documentation tells you not to use are out of scope
too, but a documentation change that prevents the misconfiguration is welcome.

## Known and accepted limitations

These are documented, deliberate, and not vulnerabilities. Do not report them;
do report a way to make one of them worse.

| Limitation | Where |
|---|---|
| An AD change (account disabled, group removed) takes **up to 6 minutes** to cut access | [ADR-0016](docs/adr/0016-n03-revocation-targets.md) |
| Revocation does not reach an **active** WebSocket/SSE connection | [ADR-0016](docs/adr/0016-n03-revocation-targets.md) |
| The whole system is a single point of failure; it fails closed | [ADR-0017](docs/adr/0017-fail-closed-availability.md) |
| AD groups are matched by **name**, so a deleted and recreated group inherits entitlements | [ADR-0008](docs/adr/0008-group-identity-name.md) |
| Upstream applications trust the network, not a signed token, to know a request came through the proxy | [docs/06-requirements.md](docs/06-requirements.md), security open questions |

## Disclosure

Coordinated. A fix and an advisory go out together; the reporter is credited
unless they ask not to be.
