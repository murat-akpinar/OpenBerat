# 0001 — v1 scope: web only (HTTP/HTTPS)

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

Will the system protect web applications, SSH/RDP, or database access as well?
This is the decision that changes the size of the project most.

## Options

| Option | Pro | Con |
|---|---|---|
| Web only | Small, one problem: an authorisation decision on an HTTP request | Server access out of scope |
| Web + SSH/RDP | More complete | Protocol brokering is a separate problem set |
| Full PAM (+DB, vault, session recording) | Commercial PAM level | Far too large for v1 |

## Decision

**Web only.** SSH/RDP is not being abandoned, only deferred — because Apache
Guacamole is itself a web application, once the web PEP works, SSH/RDP support
reduces to "define Guacamole as a protected application". Taking it on now would
let entirely separate problems (protocol brokering, session recording, password
vaulting) delay the actual work, which is the authorisation decision.

## Consequences

- No password vault, credential injection or session recording in v1.
- Guacamole integration is a v2 goal; the architecture will not block it.
- The "PAM" claim cannot be made for v1; the product's category is
  **Identity-Aware Proxy (IAP)** (with ZTNA as the umbrella term).
