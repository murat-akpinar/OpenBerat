# 03 — Keycloak ↔ Active Directory

We are **not writing** this part; we configure it in Keycloak. These notes are
research; the real settings will be verified once the lab is up.

## Connection

Keycloak Admin → Realm → **User Federation → Add LDAP provider**

| Setting | Value / note |
|---|---|
| Vendor | **Active Directory** (sets the schema mapping automatically) |
| Connection URL | `ldaps://dc01.example.local:636` — **use LDAPS**, not plain LDAP on 389 |
| Bind type | `simple`, with a service account |
| Bind DN | `CN=svc-keycloak,OU=Service Accounts,DC=example,DC=local` |
| Users DN | `OU=Users,DC=example,DC=local` |
| Username LDAP attribute | `sAMAccountName` (or `userPrincipalName`) |
| RDN LDAP attribute | `cn` |
| UUID LDAP attribute | `objectGUID` — immutable in AD, so identity survives a username change |
| User Object Classes | `person, organizationalPerson, user` |
| **Edit Mode** | **READ_ONLY** — Keycloak does not write *to AD*. It does not follow that AD is the only source of the group claim: measured (`docs/07`), a group assigned locally in Keycloak reaches the token with no `memberOf` behind it. |
| Import Users | ON (local cache) |
| Sync Registrations | OFF |
| Trust Email | ON (mail coming from AD is treated as verified) |
| **Cache Policy** | **NO_CACHE** — mandatory. Measured (`docs/07`): at `DEFAULT` a group removed in AD survives a brand-new login, with nothing bounding the delay. |

### Filter out disabled accounts

AD does not delete accounts; it disables them with a `userAccountControl` bit.
In the **Custom User LDAP Filter** field:

```
(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

**Critical, and not for the reason it looks like.** Measured (`docs/07`): AD
refuses the LDAP bind for a disabled account, so a leaver's password is refused
with this filter or without it. What the filter stops is Keycloak **importing**
them — without it a disabled account appears in the user list reported as
`enabled: true`, because Keycloak does not read `userAccountControl`, and every
path that does not end in an AD bind reaches a live account.

## Group synchronisation

User Federation → LDAP provider → **Mappers → Add mapper → `group-ldap-mapper`**

| Setting | Value |
|---|---|
| LDAP Groups DN | `OU=Groups,DC=example,DC=local` |
| Group Name LDAP Attribute | `cn` |
| Group Object Classes | `group` |
| Membership LDAP Attribute | `member` |
| Membership Attribute Type | `DN` |
| **User Groups Retrieve Strategy** | **`GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE`** |
| Mode | `READ_ONLY` |

### Choosing the strategy — this matters in AD

Keycloak offers three strategies:

| Strategy | What it does | When |
|---|---|---|
| `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE` | Scans groups looking for the user in the `member` attribute | Generic LDAP |
| **`GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE`** | Reads the user's `memberOf` attribute directly | **Recommended for AD** — AD's natural structure, better performance |
| `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY` | The first one, resolving nested groups | **If nested groups exist** |

Since we use AD, the default is `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE`.

**Nested groups:** `memberOf` shows only **direct** membership. If `Finance-All`
is a member of `OpenBerat-Finance`, a user in `Finance-All` does not see
`OpenBerat-Finance` in their `memberOf`. This is common in AD.

**Measured in Phase 1** (`docs/07`): that user gets **no `groups` claim at all**,
so a nested-group directory left on this strategy denies everything rather than
granting the wrong thing. `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY` put the
parent group in the very next token, with one field changed and no restart — and
it resolved *across* `Finance-All`, which the `(cn=OpenBerat-*)` filter excludes.
The filter bounds what the claim can name, not what the resolution may cross.
The performance cost is real but was not measured; the lab fixture is too small
to show it.

### Is group membership live, or from a cache?

Keycloak reads group membership **live from LDAP** — it queries AD on login and
on token refresh rather than waiting for a periodic sync. The source of
staleness is therefore not Keycloak but the oauth2-proxy session (ADR-0006).

**Conditional, and the condition is `NO_CACHE`.** Measured in Phase 1
(`docs/07`): at `DEFAULT` the user and their groups come from the cache, and a
**fresh login** still carries a group that AD no longer has — so the "reads
live" behaviour above belongs to the setting, not to Keycloak. `MAX_LIFESPAN`
bounds the staleness; `DEFAULT` does not bound it at all. Anything but
`NO_CACHE` and ADR-0006's single staleness layer becomes two, the second one
unbounded.

## Synchronisation timing

| Setting | Recommendation | Why |
|---|---|---|
| Periodic Full Sync | 24 hours | Catches deleted/added users |
| Periodic Changed Users Sync | 5 min | New joiners show up quickly |

**Note:** this sync is about the freshness of the user **list** (new joiners,
deletions). Group membership is already read live. The real source of
deprovisioning delay is the oauth2-proxy session — see ADR-0006.

## Putting the group claim in the token

For the PDP to make a decision, the groups have to be inside the JWT.

Client → **Client scopes → dedicated scope → Add mapper → `Group Membership`**

| Setting | Value |
|---|---|
| Token Claim Name | `groups` |
| Full group path | **OFF** (`IT-Admin` rather than `/IT-Admin`) — fix this and do not change it |
| Add to ID token / access token | ON |

Measured in Phase 1 (`docs/07`): with `GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE`
the claim follows AD within a single login — a membership added in AD is in the
next token, one removed is gone from it, with no sync and no restart.

**But the claim is a union, not a projection of `memberOf`.** A group assigned
to the user *inside* Keycloak lands in it too, with nothing in AD to support it,
and neither `READ_ONLY` nor the `(cn=OpenBerat-*)` filter reaches that path.
Since `ADMIN_GROUP` is matched on this claim by name, reading AD does not tell
you who holds admin here — see the open question in `docs/06`.

**Careful — token bloat is a real and documented problem.** The ID token of a
user in many groups grows; if the oauth2-proxy session is kept in a cookie it
exceeds the 4 KB browser limit and the cookie is split into chunks. Since nginx
normally copies only the first `Set-Cookie` header, the official example handles
this with an ugly `if` block.

**The fix has two layers:**
1. `session_store_type = redis` — the session stays on the server and the cookie
   stays small. This is also the official documentation's recommendation for
   large sessions. (It is already mandatory for the kill switch — ADR-0003.)
2. Put only this system's groups into the claim: a `OpenBerat-` prefix convention in
   AD and a matching filter in the group mapper. The token shrinks and the
   authorisation surface narrows.

Both will be applied.

## MFA

Keycloak Authentication → Flow → **Conditional OTP**. MFA is enforced for
specific groups or when a specific `acr` level is required. The PDP can apply a
"this application requires MFA" rule by looking at the `acr` claim.

Keycloak's OTP is standard TOTP: Google Authenticator, FreeOTP, Aegis and the
rest all work — the user scans a QR at enrolment and types the six-digit code
from the phone. Turning it on for everyone is realm configuration alone;
nothing in this repository changes. Only the per-application form (via `acr`)
touches our code, and that is F-21, v2 (`docs/06`).

## Kerberos / SPNEGO (optional)

Login without a password prompt on a domain-joined Windows machine. The
**Kerberos Integration** tab inside the LDAP provider. Requires a `keytab`. Not
needed for v1, but it changes the user experience considerably. Noted.

## Lab for testing

Development without a real AD:
- **Samba AD DC** (docker) — closest to real AD; the `member`/`sAMAccountName` schema is identical
- **OpenLDAP** — quick, but has no AD schema; `objectGUID`/`userAccountControl` behave differently and will mislead you
- Windows Server evaluation VM — the most accurate, the heaviest

→ Recommendation: **Samba AD DC**. The decision will be written up as an ADR.
