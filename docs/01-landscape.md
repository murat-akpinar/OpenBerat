# 01 — Existing Solutions

Before writing anything from scratch: mature open source tools already do this
job. This document exists to make clear **what we are not reinventing**.

> **Note:** Licences change often in this space (HashiCorp and Teleport both
> changed theirs in recent years). **Verify** on the project's own page before
> making a decision.

## Open source

| Tool | Category | Licence (verify) | Strength | Weakness |
|---|---|---|---|---|
| **Keycloak** | IdP | Apache-2.0 | AD/LDAP federation, OIDC + SAML, mature, CNCF. **Will be used** in this project — not a competitor. | Its authorisation engine (Authorization Services) is complex and slow; usually solved outside it. |
| **Pomerium** | IAP | Apache-2.0 (some features Enterprise) | Exactly what this project describes. OIDC + policy + portal. The closest reference. | Complex policy language; enterprise features are paid. |
| **Authentik** | IdP + Proxy | MIT | Combines Keycloak and Pomerium in one product. Has a portal and a flow editor. | Younger ecosystem than Keycloak. |
| **Authelia** | Auth portal + forward auth | Apache-2.0 | Very light, single binary, ideal for forward auth. | Not an IdP itself (it now has an OIDC provider, but not at Keycloak's level). |
| **oauth2-proxy** | Forward auth | MIT | The most minimal PEP. One binary, validates OIDC, sets headers. | No policy engine, only "did they log in". The access decision is yours to make. |
| **Teleport** | PAM / infra access | AGPL-3.0 community + commercial | SSH/K8s/DB/RDP plus session recording. The reference on the PAM side. | AGPL — be careful if productising. Heavy. |
| **HashiCorp Boundary** | PAM / access broker | BUSL (no longer open source) | Identity-based brokering to target systems. | Licence is a problem for commercial use. |
| **Apache Guacamole** | Clientless RDP/SSH/VNC | Apache-2.0 | RDP/SSH from the browser. A ready answer for the "session" part of PAM. **Do not rewrite.** | Has its own user/permission model; managing it externally needs an extension. |
| **Warpgate** | SSH/HTTP/MySQL bastion | Apache-2.0 | Small, understandable, written in Rust. A good reference to read. | Small project, limited feature set. |
| **OpenZiti** | Network-layer ZTNA | Apache-2.0 | An overlay network beneath the application layer. | Solves a different problem (L3/L4). |
| **OPA / Cedar** | Policy engine | Apache-2.0 / Apache-2.0 | Use one of these instead of writing a PDP from scratch. Rego (OPA) or Cedar (AWS). | Rego has a steep learning curve; Cedar is more readable. |
| **Casbin** | Authorisation library | Apache-2.0 | Embedded RBAC/ABAC. Lighter than OPA. | A library, not a separate service. |
| **Kasm Workspaces** | Browser isolation | Community edition available | Opens risky access in a single-use containerised browser. | Resource hungry. |

## Commercial (reference / competitor analysis)

| Product | Category | Note |
|---|---|---|
| **Cloudflare Access (Zero Trust)** | ZTNA SaaS | The UX reference for this category. Look at its portal and policy screens. |
| **Zscaler Private Access** | ZTNA | Enterprise market leader. |
| **Microsoft Entra Private Access / App Proxy** | ZTNA | In an AD environment, the biggest "you already have this" competitor. **Take it seriously** — if the customer has AD, a vendor will say "Entra already does this". |
| **CyberArk / Delinea / BeyondTrust** | PAM | Classic PAM leaders. Expensive, heavy. |
| **Wallix Bastion** | PAM | Europe-based, strong KVKK/GDPR narrative. |
| **StrongDM** | PAM / access | Modern, developer-friendly UX. |
| **Kron PAM (Krontech)** | PAM | Turkey-based domestic PAM. A direct competitor in the local market. |

## Why this project can still be written

If none of the reasons below holds, the right answer is to deploy Keycloak +
Pomerium and write configuration instead of writing this from scratch.

**Answered in [ADR-0014](adr/0014-differentiator-vs-pomerium.md).** The short
version: an operator who already runs AD has nothing new to learn (no policy
language), nothing to pay for and nothing hosted, and can read the whole system
end to end. The candidate reasons this list originally offered:

- ~~Built to learn~~ — stopped being valid the moment the project acquired users
- ~~Domestic product / KVKK / public procurement tender requirement~~ — withdrawn
  in ADR-0014: OpenBerat is not sold (ADR-0013), so a procurement argument cannot
  justify building it
- On-premises / air-gapped requirement, and the existing tools' licences block it
- The AD schema or the workflow does not fit the standard tools (approval flow, ticket integration)
- The existing tools' audit and reporting output does not satisfy the regulation

ADR-0014 also records the **trigger to abandon**: if those reasons stop being
true, this has become a worse Pomerium and should be stopped rather than
finished.

**Direct competitor set (IAP):** Pomerium, Authentik and Authelia in open
source; Cloudflare Access and Entra Private Access commercially. The
differentiator is written against these.

## Source code worth reading

In order, before writing:

1. **oauth2-proxy** — the smallest PEP. You will understand forward auth in an hour.
2. **Authelia** — a clean combination of policy, session and forward auth.
3. **Pomerium** — the target architecture as it really looks.
4. **Warpgate** — how bastion/session brokering is done.
