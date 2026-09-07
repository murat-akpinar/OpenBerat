# 0024 — v1 ships no admin screens; administration is the API

- **Status:** Accepted; superseded in part by
  [0026](0026-audit-explain-screen-in-v1.md) — the reading half. The case
  against option C (application CRUD, entitlement mapping and the kill switch
  as screens) is untouched and still holds.
- **Date:** 2026-09-07

## Context

Phase 4 is called "Minimal admin (before the portal)" and every endpoint it
asked for exists: application CRUD with `upstream_url` validation, the
entitlement mapping, nginx configuration staged and applied from the database
(ADR-0011), the audit query with its keyset cursor and six filters,
`GET /api/admin/explain`, and the kill switch. What was never built is a page to
drive them from. `frontend/src/` holds the portal, the no-access page and the
outage page; `index.html` reserves the header space with a comment saying the
admin screens do not exist.

The box was deferred once, under "Audit log viewing + filtering", for a reason
that was correct at the time: the two boxes after it added endpoints the same
screen would have to grow, so building the screen then meant building it twice.
Those boxes closed and the screen was never picked back up.

Meanwhile `docs/02` listed the frontend as "Portal + admin UI" and both READMEs
said "portal + admin" until the box was opened. That is why this is a decision
and not a silent move to *Later*: several documents described a screen set that
has never existed, and `frontend/README.md` still listed three of them by name,
row by row, in its screen table.

What v1 has instead is `INSTALL.md` §6 — the same operations driven with curl,
executed literally against the lab with a real cookie (`verify-install6.sh`),
including the `Origin` requirement, what `upstream_url` refuses, what each
entitlement field means, and `explain` as the check to make before a user tries
the path.

## Options

| Option | Pro | Con |
|---|---|---|
| **A — no screens; `/api/admin/*` is the interface** | Nothing new to write and nothing new to attack. The endpoints are already `ADMIN_GROUP`-authorised on the handler's first line, `Origin`-checked, rate-limited and logged, and §6 is a rehearsed path rather than a promise | An admin reads audit rows in a terminal. The keyset cursor and six filters have no page to be used from, and `explain` — the question an admin asks most often — answers into `jq` |
| **B — one screen: audit + `explain`** | Reading is the one thing curl is genuinely bad at. A page that walks the cursor and prints each matched/expired rule beside the verdict is where a screen earns its place, and it needs no state-changing call at all | It is still a screen on the one host every user opens, whose session cookie is valid for every application under `.apps.<domain>` (ADR-0015): an Alpine app, a CSP that has to keep holding, and a `textContent` rule that only a CI grep enforces, because there is no build step to catch a breach |
| **C — the full admin UI** | One place for everything, and the endpoints stop being documented only in an install guide | Six screens for an interface `INSTALL.md` already covers. Application CRUD and entitlement mapping are the half curl does well — a form is not the missing piece, and each screen adds surface to the portal host |

## Decision

**A.** v1 ships no admin screens. Administration is `/api/admin/*`, driven the
way `INSTALL.md` §6 shows.

The argument that keeps A over B is not that B is worthless — it is that B is
the *only* part worth building, and it is worth building on top of a v1 that
people are already running. Reading is the gap; writing is not. If exactly one
screen is ever built it is the audit-and-`explain` one, and it inherits
everything this decision leaves in place: the endpoints, their authorisation,
the vendored Alpine build and the CSP measurement behind it.

Three things make A a defensible interface rather than an absence:

- **The endpoints are the security boundary, not the screen.** `ADMIN_GROUP` is
  checked on the handler's first line, independent of the decision cache, and
  the frontend has never been allowed to make an authorisation decision
  (ADR-0007). A screen would hide buttons; it would not decide anything. Nothing
  about the boundary changes by not drawing it.
- **`explain` already answers into the terminal.** It annotates rather than
  decides — the verdict is `decide`'s own — so the answer an admin gets from
  curl is the answer the PEP gives, which is the property a screen would have
  had to preserve anyway.
- **Admin actions are already readable.** Every state-changing admin call and
  every kill switch invocation goes to the structured stdout stream with actor,
  action, target and outcome (`docs/02`, "Management plane"). An operator who
  can read container logs can already answer "who changed what".

## Consequences

- **The documents lose a screen set they never had.** `frontend/README.md`
  drops the three `Admin ·` rows from its screen table and stops opening with
  "the portal and admin UI"; `docs/02`'s directory listing and ADR-0005's follow.
  `docs/02`'s component table and both READMEs already said this before the box
  was opened — they now cite the ADR for it.
- **`/api/admin/*` is a supported interface, not an internal one.** It is the
  only way to administer v1, so its shape is now something an upgrade has to
  respect: a removed field or a renamed endpoint is a MAJOR change under
  ADR-0023, on the same footing as an environment variable being renamed.
  `INSTALL.md` §6 is its documentation and moves with it.
- **The vendored Alpine build stays, and stops being load-bearing.**
  `frontend/src/vendor/alpine.js` is now referenced by no page. It is kept
  because it is what option B re-uses and because the measurement behind it —
  the CSP build parses expressions where the standard build dies on
  `script-src blocked eval` (`docs/07`) — is worth more than the 70 KB it costs
  in an image no browser fetches it from. Three documents and a CI comment
  justified prepending its MIT notice by saying the file "is served to every
  browser that opens the portal"; that was true when written and is not now, so
  they say what is still true — it ships inside the nginx image and is reachable
  at `/vendor/alpine.js`, which is a distributed copy either way (ADR-0013).
  **If option B is never taken, the file goes**: an unreferenced dependency in a
  product that argues about `unsafe-eval` is a wart, and deleting it costs one
  commit across CI, `CONTRIBUTING.md`, ADR-0013 and the two frontend READMEs.
  The measurement in `docs/07` survives it either way.
  **Answered the other way round by [ADR-0027](0027-frontend-no-framework.md):**
  option B was taken and the screen did not want a framework, so the file goes
  anyway. The paragraph above is what it cost, and the estimate was right.
- ~~**ADR-0007 keeps its reversal trigger and loses its subject for now.**~~
  It kept the trigger and lost the subject for good
  ([ADR-0027](0027-frontend-no-framework.md)): "no Alpine at all" is the whole
  of the frontend, permanently. The trigger — open a build chain inside
  `frontend/` if the admin UI genuinely gets complex — is inherited unchanged.
- **An operator without a terminal cannot administer OpenBerat.** That is the
  real cost and it is not hidden: `INSTALL.md` §6 is a prerequisite for running
  the product, not an appendix. A site that needs a delegated, non-technical
  administrator needs option B first — which is what
  [ADR-0026](0026-audit-explain-screen-in-v1.md) then built, before the tag
  rather than after it. This bullet is the reason it was reversed.
