# 0018 — Contributions: DCO, not a CLA

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

When someone sends a patch, they hold the copyright on what they wrote. The
project's licence (ADR-0013) governs what *users* receive; it says nothing about
what the maintainer may do with a contributor's code beyond that.

That distinction matters in exactly one situation: relicensing. To offer the
codebase under different terms later, the maintainer needs permission covering
every line — including every contributor's. Without an arrangement agreed up
front, that means tracking down each contributor individually, and a single
refusal or unreachable person closes the option permanently.

The two standard arrangements:

- **DCO** (Developer Certificate of Origin) — not a contract. A one-paragraph
  statement the contributor affirms with a `Signed-off-by:` line
  (`git commit -s`): *I wrote this or have the right to submit it, and I know it
  is going in under the project's licence.* They keep their copyright and grant
  nothing extra. Used by the Linux kernel, Git and GitLab.
- **CLA** (Contributor License Agreement) — an actual contract, signed once,
  usually through a bot on the first pull request. The common form leaves
  copyright with the contributor but grants the maintainer broad rights,
  including relicensing.

## Options

| Option | Pro | Con |
|---|---|---|
| **DCO** | One `-s` flag; nobody has to read a contract; no bot, no signature records to keep | Relicensing later needs every contributor's agreement |
| CLA | Relicensing stays unilaterally possible | Real friction — some developers decline to sign CLAs on principle; needs tooling and record-keeping |
| Nothing | No work at all | The first merged patch settles the question by accident, in the worst way |

## Decision

**DCO.** `git commit -s`, checked on pull requests, described in
`CONTRIBUTING.md`.

A CLA exists to preserve the ability to relicense unilaterally, and that ability
exists to serve a commercial licence. There is no commercial licence here: the
goal is that people install OpenBerat themselves and use it free (ADR-0013).
Asking every contributor to sign a contract to protect an option nobody intends
to exercise is friction bought for nothing — and in a project that will have few
contributors to begin with, friction is the expensive thing.

"Nothing" is rejected on its own terms. The trap is not indecision, it is
merging the first outside pull request without having thought about it, which
answers the question permanently and by accident.

## Consequences

- `CONTRIBUTING.md` states the DCO requirement and the `git commit -s` mechanic.
  A pull request without a sign-off is not merged.
- **Relicensing now requires agreement from everyone who has contributed.**
  Any licence move — relaxing GPL to Apache, or tightening it to AGPL for future
  releases — stays free while the copyright is in one place, and gets harder with
  each merged patch (ADR-0013). If such a move is ever wanted, it happens before
  the project attracts contributors, not after.
- Reversing this decision is not clean: switching to a CLA later means asking
  everyone who already contributed to sign retroactively, which has the same
  one-refusal failure mode as relicensing.
- No signature infrastructure, no bot, no records to store. Anyone can contribute
  without reading a contract.
