# 0013 — Licence: GPL-3.0-or-later

- **Status:** Accepted
- **Date:** 2026-09-05
- **Note:** Two earlier drafts of this ADR chose AGPL-3.0 — first to keep an
  open-core dual-licensing option alive, then on the argument that a proxy is
  network software. Both premises are recorded below along with why they lost.

## Context

Code published without a `LICENSE` file is not open source; it is code nobody has
permission to use. Adding a licence after outside contributions arrive is a
copyright mess, so it had to be settled before the first public commit.

**The goal is that people install OpenBerat in their own environment and use it,
free of charge.** There is no commercial licence to sell and no revenue model to
protect. That removes the usual reason to reach for AGPL — preserving an
open-core dual-licensing option — and reduces the question to: what keeps this
free for the people who install it, at the lowest cost to them?

## Options

| Option | What it guarantees | What it leaves open |
|---|---|---|
| **GPL-3.0-or-later** | Anyone who receives a copy — including a modified one — gets the source. Stays free software | A modified fork run as a hosted service for others owes nothing: no copy is ever handed over, so copyleft never triggers |
| AGPL-3.0 | The same, plus §13: network use of a modified version also obliges source | Screened out by some organisations, mostly when embedding it in their own product |
| Apache-2.0 | Maximum adoption, no legal analysis to install it | Anyone may take it closed. **Not reversible** |
| BUSL / source-available | — | Not open source; contradicts the goal outright |

## Decision

**GPL-3.0-or-later.**

GPL-3 delivers the whole of the stated goal: anyone can install and run
OpenBerat for free, and anyone who passes on a modified version has to pass on
the source with it. Nothing about "people self-host it free" needs §13.

The case for AGPL was that OpenBerat is a proxy, and a proxy is network
software, so the hosted-fork hole is the one that matters. That argument is
weaker here than it looks: OpenBerat federates to the customer's Active
Directory and has to run inside the customer's network. Anyone offering it "as a
service" is in practice deploying it into someone else's infrastructure — which
is distribution, which triggers GPL-3 anyway. The scenario AGPL §13 exists for is
architecturally awkward for this particular program.

Against that narrow gain, AGPL carries a real and recurring cost: it is the
licence most often screened out by corporate policy, and the people we want
installing this are exactly the organisations that run such policies.

## Consequences

- `LICENSE` (GPL-3.0) at the root; `license = "GPL-3.0-or-later"` in
  `backend/Cargo.toml`.
- **The accepted gap, recorded so it is not rediscovered as a surprise:** a
  third party may modify OpenBerat and offer it as a hosted service without
  publishing their changes. This is a deliberate trade, not an oversight. If it
  ever happens and matters, the answer is a licence change on future versions —
  which cannot be applied retroactively to versions already released.
- Moving to AGPL later is a **tightening** and only binds future releases;
  moving to Apache later is a **relaxation** and is always possible. Both need
  the agreement of every contributor, because there is no CLA
  ([ADR-0018](0018-contributions-dco.md)) — so both get harder with each merged
  patch, and are essentially free today.
- A company installing OpenBerat for its own staff, modified or not, takes on no
  obligation at all as long as it does not pass copies outside the company.
- Vendored third-party code has to be licence-compatible. Alpine.js (ADR-0007)
  is MIT, which is compatible. The published minified build carries **no**
  notice, so one is prepended in the vendored file rather than kept only in a
  README: that file is served to every browser that opens the portal, and MIT
  asks for the notice to travel with the copy
  (`frontend/src/vendor/README.md`).
- Every file we wrote carries an SPDX identifier, checked in CI. The exception
  is `backend/migrations/`: sqlx checksums an applied migration and refuses to
  start when one changes, so a licence header there is an upgrade that breaks
  every existing installation (`docs/07`).
