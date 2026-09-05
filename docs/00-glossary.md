# 00 — Terminology

This product's category is **Identity-Aware Proxy (IAP)**. What follows are the
**industry names** for the parts of the system. These are the words used when
searching for one, buying one, or hiring for one.

## Umbrella categories

| Term | Expansion | What it means |
|---|---|---|
| **ZTNA** | Zero Trust Network Access | The model that replaces the VPN. Access is granted to individual applications, not to the network. Every request is re-verified. There is no "you are inside the network, therefore you are trusted" assumption. |
| **IAP** | Identity-Aware Proxy | ZTNA made concrete at the application layer. A reverse proxy that sits in front of the application and decides, on every HTTP request, whether this identity may reach this path. |
| **BeyondCorp** | — | The name of the architecture Google published in 2014, which popularised ZTNA. Today "BeyondCorp-style" is used generically. |
| **PAM** | Privileged Access Management | A system that brokers, records and vaults access for privileged accounts (admin, root, DBA), keeping the password from the user. Out of scope for v1 (ADR-0001). |
| **PIM** | Privileged Identity Management | Microsoft's name for PAM (Entra ID PIM). In practice the same thing. |
| **CASB / SASE / SSE** | — | Larger commercial umbrella terms that contain ZTNA. Gartner categories. Not needed for this product; they show up in tenders and marketing copy. |

**This project is an Identity-Aware Proxy (IAP).** That is how the product is
positioned: ZTNA is the umbrella term above it, PAM is a separate category and
out of scope for v1 (ADR-0001). Identity comes from Keycloak, the identity source
is AD, the decision comes from our own policy engine, and the application list
comes from the portal.

## Identity layer

| Term | What it means |
|---|---|
| **IdP** (Identity Provider) | The party that authenticates the identity. Here, Keycloak. |
| **SP / RP** (Service Provider / Relying Party) | The application that trusts the identity. Called SP in SAML, RP in OIDC. |
| **OIDC** | Identity protocol built on top of OAuth2. The modern default. Returns an `id_token` (JWT). |
| **SAML 2.0** | Older XML-based SSO protocol, still widespread in the enterprise. Needed for legacy applications. |
| **JWT / JWKS** | Token format / the public key set the IdP publishes so token signatures can be verified without asking it. (Here the per-request check is oauth2-proxy's session lookup, not a JWKS validation — the token is verified once, at login.) |
| **memberOf** | The AD attribute holding the groups a user belongs to. In this project it is the source of authorisation: `memberOf` → group → application. |
| **LDAP User Federation** | How Keycloak connects to AD. Users stay in AD, Keycloak reads them. It does not copy them into Keycloak (in READ_ONLY mode). |
| **Kerberos / SPNEGO** | SSO on a domain-joined machine without ever prompting for a password. Keycloak supports it; optional. |
| **acr / amr** | The "how strongly was this verified" information inside the token. Whether MFA happened is read from here. Used in policy for high-risk applications. |

## Provisioning (creating/updating user accounts)

| Term | What it means |
|---|---|
| **JIT provisioning** | Just-In-Time. The account is created the moment the user logs in for the first time. No prior sync needed. Keycloak's LDAP federation already does this. |
| **SCIM** | System for Cross-domain Identity Management. The IdP pushing "this user arrived / left / changed groups" to a target application over REST. A standard. |
| **Deprovisioning** | Cutting access **immediately** when a user is disabled in AD. The most frequently skipped and most critical part. |
| **Entitlement** | The record saying "this user has this level of access to this application". The "applications I can reach" list shown in the portal is technically an entitlement list. |

## Authorisation model

| Term | What it means |
|---|---|
| **RBAC** | Role-Based. AD group → role → permission. Most common, simplest. The right starting choice. |
| **ABAC** | Attribute-Based. Attributes such as device, IP, time of day, location and MFA level also feed the decision. Layered on top of RBAC later. |
| **ReBAC** | Relationship-Based. The Google Zanzibar model. "Y beneath the resource X owns." Overkill for this project. |
| **PDP** (Policy Decision Point) | The component that **makes** the decision. Answers "is this allowed?" with yes or no. |
| **PEP** (Policy Enforcement Point) | The component that **enforces** the decision. The proxy. It asks the PDP and returns 403 when the answer is no. |
| **PIP** (Policy Information Point) | An additional source of information for the decision (AD, CMDB, device inventory). |
| **Least privilege** | Default no access; access exists only where explicitly granted. |
| **Standing privilege** | Permanent entitlement. Considered bad practice in the PAM world; JIT access is recommended instead. |
| **JIT access** | Granting an entitlement on request and for a limited time rather than permanently ("prod DB for two hours"). |
| **Break-glass** | A heavily logged emergency account for when the system fails. Never left out of the design. |

## Proxy / application layer

| Term | What it means |
|---|---|
| **Forward auth** | The proxy issuing a subrequest to an external service on every request, asking "is this request allowed?". `auth_request` in nginx, `forwardAuth` in Traefik, `forward_auth` in Caddy. This project chose nginx `auth_request` (ADR-0002). |
| **Header injection** | The proxy passing the verified identity to the upstream in a header such as `X-Forwarded-User`. **Careful:** the upstream must trust only requests coming from the proxy, otherwise the header can be spoofed. |
| **mTLS** | Mutual TLS. The client presents a certificate too. Used for device identity. |
| **Device posture** | Device compliance (disk encrypted, EDR installed, patched). Requires an agent. |
| **Session recording** | Recording the session (SSH/RDP/web). PAM's distinguishing feature. For audit. |
| **Credential vaulting / injection** | Keeping the target system's password in a vault and injecting it into the session without ever showing it to the user. Classic PAM. |
| **Clientless access** | RDP/SSH from the browser with nothing installed on the user's machine. Apache Guacamole does this. |
| **App Launcher / Access Portal** | The icon list of applications a user can reach. In this project, the portal screen of `frontend`. |

## Audit

| Term | What it means |
|---|---|
| **Audit log** | Who, when, what, which decision. Must be immutable. |
| **SIEM** | Log collection/correlation system (Splunk, Wazuh, Elastic). The audit log flows here. |
| **KVKK / GDPR** | Personal data legislation (KVKK is the Turkish data protection law). Session recording and log retention are personal data processing; a retention period and a privacy notice are required. |
