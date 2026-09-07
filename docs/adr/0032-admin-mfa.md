# 0032 — MFA is required for `ADMIN_GROUP` and for nobody else

- **Status:** Accepted
- **Date:** 2026-09-07
- **Relates to:** [0008](0008-group-identity-name.md) — `ADMIN_GROUP` is the
  grant this protects, and the group the bridging role hangs on.
  [0017](0017-fail-closed-availability.md) — the way back in when the second
  factor is the thing that is lost. [0006](0006-group-membership-source.md) —
  why nothing here reaches the decision path.

## Context

The management plane is one password deep. `ADMIN_GROUP` membership plus a
password is the whole of it, and the account behind it defines applications,
maps groups to entitlements and kills sessions. The realm ships
`bruteForceProtected` with a temporary lockout, which bounds *guessing* and does
nothing about a password already known — phished, reused, or read out of a
password manager on a compromised laptop.

`docs/06` kept MFA open in a shape that could not be settled here: "for everyone
at login, or per application". Both are decisions about somebody else's
deployment — how many users, whether they carry phones, what the helpdesk can
absorb. The third answer is narrower than either and needs nobody's environment:
**required for `ADMIN_GROUP`, left alone for everyone else.** An installation
that wants MFA for all users still switches it on the way it always could; this
is the floor under the one account that can change who reaches what.

Per-application MFA is a different question. It reads `acr`, it is a rule on an
entitlement rather than a property of a login, and it stays F-21/v2.

## Decision

**The realm's browser flow asks members of `ADMIN_GROUP` for a TOTP code, and
enrols them the first time they log in.** No code in this repository changes:
the whole of it is the realm export, which is import data (`CONTRIBUTING.md`,
"configuration is baked in").

Keycloak's conditional step keys on a **role**; `ADMIN_GROUP` arrives as a
**group**. The bridge is one realm role, `openberat-mfa`, mapped onto the group
rather than onto users — a group role mapping is inherited by every member, so
membership stays the only thing an operator manages, and it stays in AD.

The flow the export ships, bound as `browserFlow`:

```
openberat-browser
├── auth-cookie                    ALTERNATIVE
├── identity-provider-redirector   ALTERNATIVE
└── openberat-forms                ALTERNATIVE
    ├── auth-username-password-form   REQUIRED
    ├── openberat-2fa-optional        CONDITIONAL   ← everyone else
    │   ├── conditional-user-role  (openberat-mfa, negate)  REQUIRED
    │   ├── conditional-user-configured                     REQUIRED
    │   └── auth-otp-form                                   ALTERNATIVE
    └── openberat-admin-otp           CONDITIONAL   ← ADMIN_GROUP
        ├── conditional-user-role  (openberat-mfa)          REQUIRED
        └── auth-otp-form                                   REQUIRED
```

Three things in that shape are the decision rather than the mechanism:

- **`REQUIRED` on the admin's OTP form, not `ALTERNATIVE`.** An `ALTERNATIVE`
  form is skipped for a user who has no OTP credential — which is every admin on
  the first day, so the control would be off exactly when it is switched on.
  `REQUIRED` sends them to enrolment instead.
- **The negated condition on the other sub-flow.** Without it a member of
  `ADMIN_GROUP` who has also enrolled OTP voluntarily matches both sub-flows and
  is asked for the same code twice. The negation is what makes "left alone for
  everyone else" true rather than approximate.
- **The flow is a trimmed copy, not the stock one.** A built-in flow cannot be
  edited, so a copy is unavoidable; the copy drops what the stock browser flow
  carries disabled or unused here — Kerberos, the Organization sub-flow, WebAuthn
  and recovery codes. Fewer executions is less to audit, and an installation that
  wants any of them adds it back where it can see the whole flow. Kerberos in
  particular is `docs/03`'s optional future, and adding it means editing this
  flow.

## Consequences

- **The first admin login of a new installation needs an authenticator app.**
  `INSTALL.md` §4 says so where the admin group is set up. This is the point of
  the ADR, not a side effect.
- **A lost phone is an admin lockout, and the way out is Keycloak's own admin
  console** — `KC_ADMIN_PASSWORD`, delete the user's OTP credential, next login
  enrols again. That is a second credential an operator already holds and
  already has to protect; it is not a new one. Break-glass (ADR-0017) is not
  the answer here: it serves applications with no authorisation at all, which is
  a heavier thing than "an admin cannot log in".
- **`ADMIN_GROUP` and the role are two names that have to agree.** An
  installation that points `ADMIN_GROUP` at its own AD group must map
  `openberat-mfa` onto that group too, or the management plane keeps working
  with no second factor and nothing says so. `INSTALL.md` §4 carries the line;
  the software cannot check it, because the backend never sees Keycloak's roles
  — it decides on group names in a header (ADR-0006, ADR-0008).
- **Nothing on the decision path changes.** No claim, no header and no
  `/decide` input is different; `acr` is not read. A second factor is a
  property of the login, and the backend's answer is the same either way.
- **Scripted admin logins have to carry a code now.** The lab's own harnesses
  are the first to feel it: a password-only `ob-login.sh` reaches the OTP page
  and stops. That is the control working, and it is also the argument against
  ever putting a service account in `ADMIN_GROUP` — a service account belongs to
  a client with its own secret, not to the group that gets an interactive
  second factor.

## Measured

`verify-adminmfa.sh` on the lab (`docs/07`), four stages: a non-admin is
untouched, an admin with no credential is sent to enrolment, an admin with one
is challenged and passes, and a wrong code leaves them with no session at all.
