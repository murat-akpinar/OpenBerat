# 0035 — MFA at login, for every user

- **Status:** Accepted. Supersedes [0032](0032-admin-mfa.md), which is kept:
  an installation that wants the narrower policy back has its flow written out
  there, execution by execution.
- **Date:** 2026-09-17
- **Relates to:** [0034](0034-read-only-management-group.md) — the auditor grant
  is an exact group-name match and does not move.
  [0021](0021-application-identity-trusted-headers.md) — why per-application
  step-up is still not reachable. [0017](0017-fail-closed-availability.md) —
  the way back in when the second factor is what is lost.

## Context

[ADR-0032](0032-admin-mfa.md) put a second factor on the management plane and
nowhere else, and said so deliberately: "an installation that wants MFA for all
users still switches it on the way it always could." It left the broader
question where `docs/06` had it, in the shape it could not settle from the
design —

> **MFA for ordinary users** — for everyone at login, or per application.

Both halves of that question are now answered, and they are answered
differently. **For everyone, at login.** Per application is not a login
property at all: it reads `acr`, it is a rule on an entitlement rather than a
fact about how somebody signed in, and it needs the `entitlement.conditions`
column and a new `/decide` input. ADR-0032 already routed it to F-21 and it
stays there — this decision does not touch the decision path.

What changes the arithmetic is scale. A second factor for two to five
administrators is a control with a rare failure mode; a second factor for every
user is a control with a routine one. That routine failure — a phone lost or
replaced — is what ADR-0032 answered with the Keycloak admin console under
`KC_ADMIN_PASSWORD`, and that answer was sized for the small set. It does not
survive this change. It is named in Consequences and it is not solved here.

## Decision

**The realm's browser flow asks every user for a TOTP code after the password,
and enrols them the first time they log in.** No code in this repository
changes: the whole of it is the realm export, which is import data
(`CONTRIBUTING.md`, "configuration is baked in").

```
openberat-browser
├── auth-cookie                    ALTERNATIVE
├── identity-provider-redirector   ALTERNATIVE
└── openberat-forms                ALTERNATIVE
    ├── auth-username-password-form   REQUIRED
    └── auth-otp-form                 REQUIRED
```

The change **deletes more than it adds** — four lines in, ninety-five out. Gone
are the realm role `openberat-mfa`, its two group mappings, both conditional
sub-flows, both `conditional-user-role` executions, the `negate` configuration
and `conditional-user-configured`. Eight executions become two.

Two of ADR-0032's three deliberate details go with them, because they were both
consequences of having two branches: the negated condition existed only to stop
an admin who had also enrolled voluntarily from being asked for the same code
twice, and the role existed only to key a conditional step on something
Keycloak would evaluate. With one branch there is nothing to negate and nothing
to key.

The third detail is kept, for the reason it was written: **`REQUIRED` on the
OTP form, not `ALTERNATIVE`.** An `ALTERNATIVE` form is skipped for a user who
has no OTP credential, which is every user on the first day — the control would
be off exactly when it is switched on. `REQUIRED` sends them to enrolment.

## Consequences

- **A lost or replaced phone is now everybody's problem.** ADR-0032's way out —
  the Keycloak admin console, `KC_ADMIN_PASSWORD`, delete the credential, next
  login enrols again — was a defensible answer for a handful of admins and is
  the wrong one for a whole directory: it makes a routine helpdesk task reach
  for the realm-master credential, and a credential reached for often is a
  credential that gets shared. **A reset path in the management plane becomes
  work**, and it is deliberately not this ADR. The measured ground for it is in
  `docs/07`: the backend's existing service account, the one the kill switch
  uses, already answers `200` to a username query and to reading a user's
  groups, and its `DELETE` on a credential answers `404` rather than `403` —
  the permission is already held, only the HTTP surface is missing.
- **ADR-0034 is untouched.** `AUDITOR_GROUP`'s read-only grant was never the
  role; both group checks are exact name matches on what oauth2-proxy put in
  the header (ADR-0021 on the `role:` prefix).
- **`/api/me`'s `groups` loses `role:openberat-mfa`.** It granted nothing and
  was only the direct evidence that the group mapping had reached the member
  (`docs/07`); with no role there is nothing to inherit.
- **Nothing on the decision path changes.** No claim, no header and no
  `/decide` input is different; `acr` is still not read, `policy.rs` is not
  touched, and N-01/N-02 are unaffected. A second factor stays a property of
  the login, and the backend's answer is the same either way.
- **Users who already enrolled keep their credential** and get the challenge
  rather than the QR. Only a user with no OTP credential meets enrolment. On a
  lab this is invisible, because Keycloak runs on H2 with no volume and a
  rebuild re-imports the realm and drops every enrolment with it; an
  installation with a Keycloak database keeps them.
- **Day one costs the operator an enrolment for every user.** There is no grace
  period and no partial rollout: the flow is bound realm-wide. That is the
  point of the control, not a side effect, and an installation that cannot
  absorb it reverts to ADR-0032's flow.
- **Scripted logins still have to carry a code, and the argument against
  service accounts as users gets stronger, not weaker.** Anything
  non-interactive belongs to a client with its own secret. That this is
  workable is not a hope: the lab's `ob-login.sh` keys on what the login page
  returns rather than on the username, so it enrols on first sight of
  `totpSecret` and answers the challenge from the per-user secret afterwards —
  thirty-eight harnesses drive logins through it and none of them needed a
  change.

## Measured

`verify-mfaall.sh` on the lab (`docs/07`): a user who had never been asked for
a second factor is sent to enrolment, the same user is challenged on the next
login, a wrong code leaves no session, and an authorised application request
still answers `200` afterwards — the decision path unchanged.
