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

This is a design-stage project — **there is no released version yet** and no
deployment to attack. Until v1 ships, the useful report is a flaw in the design
itself: a way around the decision path in `docs/02-architecture.md`, a rule in
`docs/05-authz-model.md` that does not hold, or a configuration in
`docs/03-keycloak-ad.md` that is unsafe as written.

In scope once code exists: the authorisation decision, the `/decide` contract,
header spoofing, the nginx configuration this project generates, session
handling and revocation, and the admin API.

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
