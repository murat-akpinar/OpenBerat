# 0010 — Lab AD: Samba AD DC

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

Phase 1 verifies the architecture against a real directory before any code is
written. Development cannot depend on the customer's production AD, so the lab
needs its own directory server — and the first item of Phase 1 is the
`docker-compose.yml` that includes it.

The choice matters more than it looks: three of the Phase 1 verifications
(`userAccountControl` filtering, `memberOf` behaviour with nested groups,
`objectGUID` as the immutable id) test AD-specific schema behaviour. A directory
that merely speaks LDAP will pass tests that real AD would fail.

## Options

| Option | Pro | Con |
|---|---|---|
| **Samba AD DC** (docker) | A real AD domain controller: same `member`/`sAMAccountName`/`objectGUID`/`userAccountControl` schema | Heavier than OpenLDAP; some group policy features absent |
| OpenLDAP | Fastest to start | **No AD schema.** `objectGUID` and `userAccountControl` behave differently — it will pass tests that production fails |
| Windows Server evaluation VM | The most accurate | Heaviest; a licence clock; awkward in CI and on a laptop |

## Decision

**Samba AD DC**, as a container in `docker-compose.yml`.

OpenLDAP is disqualified on correctness, not on convenience: the specific things
Phase 1 sets out to verify are the specific things OpenLDAP does not model. A
green test against the wrong schema is worse than no test.

Windows Server stays as the escalation path. If a Phase 1 verification produces
a surprising result, it is re-run against a Windows Server evaluation VM before
the architecture is changed on the strength of it — Samba is close to AD, not
identical to it.

## Consequences

- `docker-compose.yml` carries a `samba-ad` service, and the lab comes up with
  `docker compose up` on one machine (N-05).
- Test users, nested groups and disabled accounts are fixtures created in this
  container, so Phase 1's measurements are reproducible.
- **Samba is not AD.** Any Phase 1 finding that contradicts documented AD
  behaviour is re-tested on Windows Server before it is believed. This applies
  especially to the nested-group `memberOf` test, where Samba's and AD's
  behaviour is the very thing under examination.
- **The lab host cannot be a user namespace.** Provisioning writes
  `security.*` extended attributes, which an unprivileged container refuses
  whatever capabilities it is given — bare metal, a VM or a privileged
  container is required (`docs/07`). This does not change the decision; it is
  the ground the decision needs, and N-05's "one machine" now carries a
  condition on which machine.
- The lab is a development dependency only; it ships in no release image.
