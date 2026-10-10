# 0039 — Deprovisioning is disabling the account, not letting it expire

- **Status:** Accepted
- **Date:** 2026-10-10
- **Relates to:** [0016](0016-n03-revocation-targets.md) — whose six-minute
  row names the two AD changes it covers, and this says which ones it does not;
  [0006](0006-group-membership-source.md) — the refresh that carries an AD
  change into a session.

## Context

ADR-0016 promises that an account **disabled** in AD, or removed from a group,
loses access within six minutes. AD has two more ways to stop an account that
look like deprovisioning from the outside: `accountExpires` (contractors are
often given an end date and nothing else) and lockout after bad passwords.

Security audit run-1 asked whether a session survives either. Measured on the
lab (`docs/07`, lead 10 re-run): both sessions refreshed at the first
`cookie_refresh` and stayed 200, like an untouched control, while a fresh
login for either was refused. A refresh does not bind to AD. What Keycloak does
read on it — the provider's filter and the MSAD account-control mapper — looks
at the disable bit only. So an expired or locked-out account keeps every
application it is entitled to until `cookie_expire` / `ssoSessionMaxLifespan`,
10 hours.

## Options

| Option | Pro | Con |
|---|---|---|
| A. **Write it down: deprovisioning is disable or group removal**, and give installations that rely on expiry a scheduled task that disables expired accounts | No new component; the measured path stays the only one; matches what AD itself does with an expired account's open Windows session | One more thing an installation has to run if it uses end dates |
| B. Shorten `cookie_expire` / `ssoSessionMaxLifespan` | One value | Bounds the gap without closing it, and every user signs in with a password and a code more often |
| C. Read `accountExpires` and `lockoutTime` ourselves on each refresh | Closes it | A new component that talks LDAP — the backend has none — or a Keycloak SPI in Java: a new trust boundary for one attribute |

## Decision

**A.** The deprovisioning signals are the two ADR-0016 measured: the disable
bit and group membership. Lockout is not one: it exists to stop guessing, and
the session it would end belongs to whoever signed in before the guessing
started. Expiry is one in practice, so `INSTALL.md` §8 gives the task that
turns it into a disable — an LDAP filter for accounts whose `accountExpires`
is past and that are not yet disabled, run on a schedule. Measured end to end
on the lab: the task disabled the expired account, and its session ended at the
next refresh while the control's went on. C is refused for the boundary it
adds; B stays available to an operator and is not the product's answer.

## Consequences

- N-03's six minutes, for an expired account, is the task's interval plus six
  minutes. An installation that runs the task hourly should say "about an hour"
  to whoever relies on end dates.
- A locked-out account's open sessions continue until the realm's 10 h. The
  kill switch is the answer when that is not acceptable, as it already is for
  any session that has to end now.
- The PowerShell form of the task in `INSTALL.md` is not tested here, because
  the lab DC is Samba (`docs/07`, Unverified); the LDAP filter it uses is.
- Reversing it is C: a component that reads AD on refresh. Nothing stored
  depends on this decision.
