# 0014 — Why we are building this instead of deploying Pomerium

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

`docs/01` lists mature tools that already do this job — Pomerium and Authentik
in the open, Cloudflare Access and Entra Private Access commercially — and
states plainly that if none of its five justifications holds, the right answer
is to deploy Keycloak + Pomerium and write configuration instead.

That question was carried as the most expensive open decision in the project and
the only one with no ADR. It gates the Phase 2 schema: an audit-led
differentiator pulls the audit hash chain forward into `0001_init.sql`, a
compliance-led one pulls reporting forward, and a "we are not different" answer
stops the project.

"Because we are learning" stopped being available the moment the project
acquired users: ADR-0012 gave it a public name and ADR-0013 a licence, so other
people will install it and depend on it.

## Options

| Option | Consequence |
|---|---|
| Deploy Pomerium, write config | Correct if none of the differentiators below holds. Weeks instead of months |
| Deploy Authentik | Replaces Keycloak too; one product instead of five components; a bigger surface to audit |
| Build OpenBerat | Only justified by the reasons below, in writing |

## Decision

**Build it**, on three differentiators.

1. **AD-native authorisation with no policy language.** Pomerium and Authentik
   both make the operator learn a policy model. Here the model is the one the
   customer's AD already encodes: group → application, allow or deny, in a
   table an admin edits in a form (ADR-0009). For an organisation whose access
   rules already live in `memberOf`, there is nothing new to learn, and no
   second source of truth to keep in sync.

2. **On-premises and air-gapped by construction, not by configuration.** One
   `docker compose up` on one machine (N-05), configuration baked into images
   (`CONTRIBUTING.md`), no CDN and no npm tree (ADR-0007), an offline bundle in
   Phase 6.
   Nothing phones home, and there is no paid tier that unlocks a feature the
   installation needs — where Pomerium's enterprise features are licensed.

3. **Small enough to audit end to end.** Two components we wrote, five
   off-the-shelf parts, every decision written down as an ADR with its
   consequences and its accepted debts (ADR-0008 is a worked example). For a
   security review, a KVKK assessment or a procurement questionnaire, "here is
   every decision and every dependency" is a property a larger product cannot
   offer at all.

The fourth candidate from `docs/01` — domestic product / KVKK / public
procurement — is **withdrawn.** It was a commercial argument, and ADR-0013
settled that OpenBerat is not sold: people install it themselves and use it
free. A procurement requirement cannot justify building software nobody is
selling.

That withdrawal makes this decision **harder to defend, not easier**, and the
record should say so. "We would make money" is off the table, so the only
remaining justification is what a person who installs this actually gains over
installing Pomerium. Differentiators 1–3 have to carry that weight by
themselves. They are, in short: an operator who already runs AD has nothing new
to learn, nothing to pay for, and can read the whole thing.

## Consequences

- **The honest counter-position, kept on the record:** Pomerium is technically
  ahead — device posture, more identity providers, a mature policy engine, years
  of production exposure. If a prospective user has none of the constraints
  above, recommending Pomerium is the correct answer, and this ADR is the reason
  why that is not a contradiction.
- **The trigger to abandon:** if differentiators 1–3 stop being true — an
  operator-facing policy language creeps in, a hosted or licensed component
  becomes necessary, or the component count grows past what one person can
  audit — the project has become a worse Pomerium and should be stopped rather
  than finished. With the commercial argument withdrawn, this trigger is the
  only thing standing between the project and that outcome, so it is worth
  re-reading at the end of each phase.
- **Schema consequence, which is what this decision was gating:** none of 1–3 is
  audit-led, so the audit hash chain (`prev_hash`) stays out of
  `0001_init.sql` and remains a "later" item. `audit_event` keeps the summary
  columns it already has (`docs/02`). Phase 2 is unblocked.
- Differentiator 1 is a design constraint, not a slogan: any feature that would
  require the operator to learn a policy syntax has to be weighed against it.
