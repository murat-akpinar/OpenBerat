# 0033 — The management screen writes: application and entitlement CRUD in v1

- **Status:** Accepted
- **Date:** 2026-09-07
- **Supersedes in part:** [0024](0024-no-admin-ui-in-v1.md) — the writing half.
  With this, nothing of ADR-0024's decision is left standing:
  [0026](0026-audit-explain-screen-in-v1.md) took the reading half and this
  takes the rest. The kill switch is **not** part of it —
  [0028](0028-live-sessions-endpoint.md) refused a kill button on its own
  grounds and those grounds are untouched.

## Context

[ADR-0024](0024-no-admin-ui-in-v1.md) chose option A — no screens — over option
C, which was named exactly: *"application CRUD, entitlement mapping and the kill
switch as screens"*. Its case against C is one sentence:

> Six screens for an interface `INSTALL.md` already covers. Application CRUD and
> entitlement mapping are the half curl does well — a form is not the missing
> piece, and each screen adds surface to the portal host.

Two of those three clauses stopped being true when
[ADR-0026](0026-audit-explain-screen-in-v1.md) built the screen, and the third
was never the reason.

- **"Six screens"** was the cost of a screen set built from nothing. There is
  now one page with three tabs, a fetch helper that already tells 403 from 503,
  a notice element, a `textContent`-only rendering rule and the CSS for tables
  and forms. Applications and Access are two more tabs on it.
- **"each screen adds surface to the portal host"** — no endpoint is added and
  no boundary moves. ADR-0024 established the principle itself: *"The endpoints
  are the security boundary, not the screen."* It cuts this way too. A form
  sends the JSON curl sends, to the handler that checks `ADMIN_GROUP` on its
  first line independent of the decision cache, past the same `Origin` check,
  the same rate limit and the same F-14 log line. What is added is markup, on
  the host that already serves an admin screen.
- **"curl does writing well"** is true for whoever wrote the API. ADR-0024 named
  the real cost in its own consequences — *"An operator without a terminal
  cannot administer OpenBerat"* — and ADR-0026 fired on that sentence for
  reading. The sentence does not distinguish reading from writing. The shape it
  leaves is worse than either half alone: the operator is shown why a user was
  denied, is shown the rule that denied them, and then has to leave the page and
  open a terminal to change it.

The timing argument is ADR-0026's, unchanged and not weakened by having been
used once. **No version is tagged.** Nothing is deployed, so there is no
operator to re-train, no upgrade to plan and no interface promise to keep. After
the tag all three exist.

## Options

| Option | Pro | Con |
|---|---|---|
| **A — writing stays curl (ADR-0024's decision)** | Nothing new to write. `INSTALL.md` §6 is rehearsed against the lab with a real cookie | The operator who has just been shown *why* a user was denied is sent to a terminal to fix it. F-06 and F-07 have a screen for reading their effects and none for causing them |
| **B — application and entitlement CRUD as two more tabs** | The endpoints exist, are tested against a real Postgres and are already authorised, `Origin`-checked and logged. The screen exists. What is missing is two forms and two tables | Two tabs of markup on the portal host, and the `textContent` rule now has to hold on pages that also read values back out of forms |
| **C — B plus a kill button on the Live tab** | F-09 is the one admin action where seconds matter, the endpoint is 0.085 s end to end, and the row already knows the subject | ADR-0028 refused it for a reason this decision does not touch. Its *"nothing on it writes"* premise does fall here — but *"a defence against a mis-click on the wrong row"* stands on its own, and a mis-click that revokes a person's access is not undone by clicking again |

## Decision

**B.** v1 ships application CRUD and entitlement mapping as two tabs on the
management screen ADR-0026 built. Revocation stays `POST /api/admin/kill/{sub}`,
run deliberately from a terminal.

Four things this decision explicitly does **not** change:

- **The frontend still decides nothing.** Both tabs draw whatever the API
  returns and hide nothing from anyone: a user outside `ADMIN_GROUP` who types
  the URL gets the same 403 sentence the reading tabs give them, because the
  check is on the handler and not on the page.
- **No validation is duplicated.** `validate.rs` owns what a slug, an
  `upstream_url`, an `external_hostname` and a `path_pattern` may be. The form
  sends what was typed and prints the sentence that comes back. A copy in
  JavaScript would drift from the one in front of the database, and the one in
  front of the database is the one that is load-bearing.
- **Create-only fields stay create-only.** `slug` and `external_hostname` are
  not patchable and the form does not offer them on an edit — `admin.rs` says
  why: both are written into generated nginx blocks and into every audit row
  that names the application, so renaming one silently reassigns history.
- **`INSTALL.md` §6 stays the interface's documentation.** Under ADR-0023 the
  API is the supported management interface and a removed field is a MAJOR
  change. The screen is a client of it, not a replacement for it.

## Consequences

- **v1's administration story becomes: everything except revocation, without a
  terminal.** That is the sentence to hold this decision to. The exception is
  deliberate and is ADR-0028's.
- **A delete says what it takes with it.** `delete_application` removes the
  application's entitlements and leaves its audit rows, which carry the slug and
  no foreign key. The confirmation names both halves, because the second one is
  the surprising one and it is the reason the first is safe to offer at all.
- **`"nginx": "staged"` becomes visible.** Every write to an application
  re-renders the generated configuration (ADR-0011) and the handler already
  returns whether that succeeded. Curl users saw it; now the screen says it,
  because "saved but not published" and "saved and live" are the two states an
  admin has no other way to tell apart.
- **The header link is `Admin`, not `Audit`.** It was named after the one tab
  that existed.
- **The CI frontend grep guards more than it did.** Everything from the API is
  still written with `textContent`; what is new is values read back out of
  forms, which the same grep covers because the rule it enforces is about the
  sink and not about the source.
- **`frontend/README.md` and `docs/02` regain screen rows ADR-0024 deleted** —
  not the rows it deleted. Three admin screens came back as two tabs.
