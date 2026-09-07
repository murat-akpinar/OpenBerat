# 0027 — The frontend carries no framework; the vendored Alpine build is removed

- **Status:** Accepted
- **Date:** 2026-09-07
- **Supersedes in part:** [0007](0007-frontend-buildless-static.md) — the
  framework half of its decision. "Buildless static, no npm, no CDN" stands and
  is the whole of it now.

## Context

[ADR-0007](0007-frontend-buildless-static.md) decided **HTML + CSS +
Alpine.js**, one file vendored by hand, and it said why: an SPA framework is
unnecessary for a handful of screens that list JSON, and a security product
arriving with hundreds of npm packages contradicts its own claim. Both reasons
are still right. Only the middle term is in question — whether *any* runtime
framework is needed for the screens that actually exist.

The screens that exist are the portal, `/denied`, `/unavailable`, and now the
audit + `explain` screen ([ADR-0026](0026-audit-explain-screen-in-v1.md)). The
first three were written in plain DOM calls with no Alpine at all, and
`portal.js` is 104 lines of it. So the question ADR-0007 could only guess at in
Phase 0 — how much a framework saves on our screens — can now be answered by
looking at the one screen where it would have helped most: six filters, a table
and a keyset "load more".

The vendored file is `@alpinejs/csp@3.17.1`, chosen over the standard build on a
measurement (`docs/07`, "Alpine.js under `default-src 'self'`"): the standard
build loads under that policy and then evaluates nothing, every binding blocked
as `eval`, because it compiles expressions with `new Function()`. That
measurement is what made Alpine usable here at all, and it is not in question
either — it stays in `docs/07` whatever this decides.

## Options

| Option | Pro | Con |
|---|---|---|
| **Plain DOM, no framework** | One idiom across all four pages. The CI rule that keeps the frontend to text (`innerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`) already covers every line, because every line is ordinary JavaScript. Nothing vendored, nothing to upgrade by hand, 70 KB out of the image | The audit page is roughly twice the JavaScript it would be with `x-for`/`x-model`. Filter state is held by hand |
| Alpine, as ADR-0007 planned | Less code on the one page with filter state. The vendored build finally gets loaded, and its CSP measurement is exercised by a real page rather than a probe | **The text-only rule stops being enforced.** The CI grep looks for `innerHTML` and friends; Alpine's `x-html` is an attribute in our own HTML and matches none of it, so the guard has to be re-implemented for a second syntax — on the host whose cookie is valid for every application under `.apps.<domain>` (ADR-0015). A vendored dependency, a manual upgrade path and a checksum table stay in the tree for one page |

## Decision

**No framework.** The audit + `explain` screen is written the way `portal.js` is
written — `createElement` and `textContent` — and `frontend/src/vendor/` is
deleted.

The deciding argument is not the line count, which favours Alpine. It is that
the frontend's one hard rule — *write text, never markup*, because an
application name an admin typed is rendered on the host holding a cookie valid
for every application (ADR-0015) — is enforced by a CI grep and nothing else,
since ADR-0007 bought no build step to catch a breach. That grep is exact
against plain DOM calls and blind to `x-html`. Adopting a second templating
syntax means re-deriving the guard for it, and a guard written twice against one
rule is how the rule ends up half-enforced.

ADR-0007's own reasoning points the same way once its guess is replaced by a
count: it kept the framework for "admin CRUD ergonomics", and ADR-0024 removed
CRUD from the frontend for good. What remains is a table and a form.

**The reversal trigger from ADR-0007 is inherited unchanged**: if the frontend
genuinely gets complex, open a build chain inside `frontend/`. It now has one
more precondition, which is the honest one — a build step is also what would
make the text-only rule enforceable by something better than a grep.

## Consequences

- **`frontend/src/vendor/` is deleted**, README and all: 70 KB, one vendored
  dependency, one manual upgrade procedure and one checksum table leave the
  tree. `/vendor/alpine.js` stops being a URL the nginx image serves.
- **CI loses its vendor rules and keeps its real one.** The `frontend` job drops
  the `@alpinejs/csp` `eval`/`new Function` check and the MIT-banner check; the
  text-only, no-inline-`<script>`, no-inline-handler rules apply to every file
  under `frontend/src/` with no exception carved out for a vendor directory.
  The `licence` job loses its `VENDOR` map — every file in the tree is now ours
  and under GPL-3.0-or-later, which is what [ADR-0013](0013-licence-gpl.md)
  wanted anyway and had to make one exception for.
- **The `docs/07` measurement survives its subject.** "Alpine.js under
  `default-src 'self'`" stays: it is a fact about Alpine and a CSP, it is what
  the next person reaching for a framework needs to read before they vendor the
  standard build, and deleting a finding because we stopped needing it is how a
  reference file becomes a sales document. It gains one line saying the file it
  was measured on is gone.
- **The CSP does not change.** `default-src 'self'` with no `unsafe-inline` and
  no `unsafe-eval` was already what the portal ran under; removing the only
  script that could have wanted `unsafe-eval` narrows nothing and loosens
  nothing.
- **ADR-0024's "if option B is never taken, the file goes" is answered the other
  way round.** Option B was taken ([ADR-0026](0026-audit-explain-screen-in-v1.md))
  and the file goes anyway, because the screen did not need it. Same disposal,
  a different reason, and the reason is worth writing down: the file was kept
  for a use that turned out not to want it.
