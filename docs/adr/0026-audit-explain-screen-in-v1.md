# 0026 — The audit and `explain` screen ships in v1

- **Status:** Accepted
- **Date:** 2026-09-07
- **Supersedes in part:** [0024](0024-no-admin-ui-in-v1.md) — the reading half.
  Application CRUD and entitlement mapping stay curl-driven, as it decided.

## Context

[ADR-0024](0024-no-admin-ui-in-v1.md) chose option A — no admin screens at all —
over option B, which was *one* screen: the audit list and `explain`. It was
explicit that B is not worthless:

> The argument that keeps A over B is not that B is worthless — it is that B is
> the *only* part worth building, and it is worth building **on top of a v1 that
> people are already running**.

That sentence is a trigger, and reading it again is what opened this decision.
**No version is tagged.** `release.sh` builds the bundle and ADR-0023 keeps
cutting the tag a deliberate manual act, so there is no v1 anybody is running
and there never will be one that the trigger, taken literally, can fire on:
the first tag would be the one that ships without the screen.

Nothing about the cost side changed either. ADR-0024 named the real cost itself
and did not hide it: *"An operator without a terminal cannot administer
OpenBerat."* `/api/admin/audit` carries a keyset cursor and six filters that
refuse rather than widen, `/api/admin/explain` annotates a decision with every
rule it walked marked matched and expired, and **no page uses either**.

## Options

| Option | Pro | Con |
|---|---|---|
| **Build it now, before the tag** | The cheapest moment there will ever be. Nothing is deployed, so there is no upgrade to plan, no operator to re-train and no interface promise to keep — v1 goes out able to answer "why was this denied" without a terminal | ADR-0024's stated order is reversed within days of it being written |
| Tag v1 first, build it second | The trigger fires literally, and the screen lands on a product with real usage behind its design | The first release is the one with the cost ADR-0024 named, and the operators who most need the screen are the ones who meet the product without it |
| Leave it in *Later* | Nothing to do | The endpoints stay written-and-unused indefinitely, and the vendored Alpine build has no reason to exist either way |

## Decision

**Build it now, before the first tag.** v1 ships one admin screen: the audit
list and `explain`, both read-only.

The trigger in ADR-0024 was reasoning about *risk of building the wrong screen*,
and it picked the wrong proxy for it. What protects against building the wrong
screen is that this one makes no state-changing call and adds no endpoint —
it draws what two existing endpoints already answer. Waiting for usage buys
nothing that a page with no write path can spend.

Scope, and the line is the same one ADR-0024 drew:

- **In:** the audit list with its six filters and keyset paging, and the
  `explain` form with the walked rules beside the verdict.
- **Out:** application CRUD, entitlement mapping, the kill switch. Those are
  writes, `INSTALL.md` §6 covers them, and a form is not the missing piece.
  ADR-0024's option C is still refused.

## Consequences

- **The screen decides nothing.** It renders `/api/admin/audit` and
  `/api/admin/explain`, both already `ADMIN_GROUP`-checked on the handler's
  first line, independent of the decision cache. A non-admin who opens the page
  gets 403s from the API and an empty table with the reason on it — the boundary
  is the endpoint, exactly as ADR-0024 said, and drawing it does not move it.
- **No new endpoint, and no new state-changing call**, so nothing new is
  `Origin`-checked, rate-limited or audited. The `POST` surface of the portal
  host is unchanged.
- **`explain` inherits its one honest disagreement.** It reads the entitlement
  table while the PEP may still be answering from a cache entry, so for up to
  `cache::TTL` after a rule change the screen is right and the live URL is
  stale. That is the intended direction and it is now visible to more people, so
  the screen says so on the page rather than only in a doc comment.
- **`/api/admin/*` was already a supported interface** under ADR-0023 and stays
  one. The screen is a second consumer of it, not a replacement — a removed
  field still breaks curl users, and the compatibility rule ADR-0024 set does
  not loosen because a page now exists.
- **The frontend gains a second page on the portal host**, which is the host
  whose session cookie is valid for every application under `.apps.<domain>`
  (ADR-0015). The CSP, the `textContent`-only rule and the CI grep that enforces
  it all apply to it unchanged — see [ADR-0027](0027-frontend-no-framework.md),
  which is the same decision seen from the framework side.
- **ADR-0024 keeps its argument and loses its verdict.** Its case against option
  C — six screens for an interface `INSTALL.md` already covers — is untouched
  and is why the scope line above exists. Only the "and not B either" half is
  reversed.
