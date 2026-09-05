# 0009 — Policy engine: our own code, not OPA

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The PDP has to turn (identity, groups, application, path) into allow or deny.
Either we write that, or we embed a policy engine — OPA/Rego, Cedar or Casbin.

`docs/05` has recommended our own code since the design phase without the
decision ever being recorded. This ADR records it and, more usefully, writes
down the trigger that reverses it.

## Options

| Option | Pro | Con |
|---|---|---|
| **Our own code** | The decision order is a six-step function; debuggable; nobody has to learn a DSL | A rewrite if rules get genuinely complex |
| OPA / Rego | Industry standard, policy separated from code | ~300 lines of Rego, one more service, a steep learning curve |
| Cedar | More readable than Rego, formally verifiable | Smaller ecosystem, still a DSL |
| Casbin | Embedded, light | The model file is a DSL too |

## Decision

**Our own code, in `policy.rs`.**

The rule set is small and closed: default deny, deny beats allow, optional
path pattern, expiry. That is a function, not a language. Every engine above
would be introduced to express five rules, and each brings a syntax that has to
be learned before an outage can be debugged at 3 a.m.

The pure-function constraint (no DB, no HTTP, no clock in `policy.rs` —
`CONTRIBUTING.md`) buys most of what a policy engine is sold for — the decision is
testable in isolation, and every row of the path normalisation table in
`docs/05` is a unit test.

## The trigger

This reverses when **any** of these becomes true:

1. A rule needs data the decision inputs do not carry (`docs/05`, "Decision
   inputs") and adding it would mean threading a new source through `policy.rs`.
2. Customers need to author or read policy themselves, rather than an admin
   ticking allow/deny in the UI.
3. The condition set from F-21 (IP range, `acr`, time window) grows past what
   reads clearly as a chain of ifs.

Note that (3) is the likely one, and it arrives with v2. Reversing is cheap by
construction: `policy.rs` is pure, so it can be swapped for a call to an engine
without touching `/decide`, the cache or the store.

## Consequences

- No new service, no new language, no new dependency in v1.
- `policy.rs` is the single place an authorisation decision is made, and it is
  the file with the strictest test requirement in the repository
  (`CONTRIBUTING.md`).
- The ABAC conditions of F-21 are the first real test of this decision. If they
  arrive as a JSON blob of ad-hoc operators, that is the signal from trigger (3),
  not a reason to invent a small DSL of our own — which would be the worst of
  both options.
