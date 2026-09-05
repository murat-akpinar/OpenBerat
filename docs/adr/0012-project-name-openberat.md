# 0012 — Project name: OpenBerat

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The project shipped without a name; the directory was `project-x` and both
`README.md` and the working conventions file carried placeholders. `TODO.md` listed the name as a
Phase 2 blocker because it reaches the Cargo package name, the container images,
the realm export and every document.

The project will be released as open source, so the name has to survive outside
the team: it needs a free crates.io name, a free GitHub organisation and a free
domain, and it must not collide with an existing product in the identity or
security space.

Two naming routes were considered:

1. **Category as name** — `OpenIAP`, `OpenZTNA`. Rejected. This lane is
   exhausted (OpenAM, OpenIAM, OpenIDM, OpenZiti are all taken) and `OpenIAP`
   collides with OpenIAP ApS, an existing company.
2. **A historical artefact that proves identity or grants a right.** The product
   is a gate that reads who you are and decides what you may reach; naming it
   after the physical object that used to do that job is accurate rather than
   decorative.

## Options

Every candidate was checked against crates.io, `github.com/<name>` and RDAP for
`.io` / `.dev` before being considered.

| Candidate | Meaning | Outcome |
|---|---|---|
| **OpenBerat** | *Berat* — an Ottoman warrant: the document granting a person an office, a privilege or a right | **Chosen.** crates.io, GitHub org and `openberat.io` all free |
| OpenTessera | *tessera hospitalis* — a Roman token split in two, the halves matching to prove identity | Free, strong meaning, but Italian "tessera" already means identity card and the word reads as mosaic tile |
| OpenTamga | Turkic clan seal stamped to show ownership and belonging | Free; a small Python logging library already uses `Tamga` |
| OpenKapi | *kapı* — door | Free, but shadowed by the Okapi Framework and the Rust `okapi` crate |
| OpenBulla | Mesopotamian sealed clay envelope; Roman status amulet; papal lead seal | Free, kept as the fallback |
| OpenIAP | the category name | Rejected — OpenIAP ApS |
| OpenBarbican | fortified gatehouse | Rejected — OpenStack Barbican is a secret store, a direct collision in security |
| OpenTally, OpenSignet, OpenHanko, OpenPylon, OpenWarden | split tally stick, signet ring, Japanese seal, temple gateway, guard | Rejected — GitHub organisation already taken |
| Shibboleth | the biblical password test | Rejected — Internet2's SAML federation software, permanently unusable |

## Decision

**OpenBerat.**

A *berat* is the closest historical object to what this product actually issues:
not proof of who you are, but a warrant stating what you are permitted to do.
Authentication is delegated to Keycloak and oauth2-proxy (ADR-0003); the only
thing this codebase decides is authorisation. The name describes the part we
wrote.

It is also ASCII-clean. Unlike `kapı`, `geçit` or `nöbetçi`, "Berat" loses no
diacritic when written as a package name, a hostname or a crate, and it reads
the same in Turkish and in English.

Known cost: *Berat* is a common Turkish given name and the name of a religious
night (*Berat Kandili*). This makes plain-word search noisy, but no software
product, crate or GitHub organisation carries the name.

## Consequences

- `backend/Cargo.toml` package name becomes `openberat`.
- The `README.md` and `docs/06-requirements.md` placeholders are resolved; the "project name" item leaves the open questions list.
- The Keycloak realm export is named `openberat-realm.json`.
- The AD group prefix was subsequently settled as `OpenBerat-` in
  [ADR-0008](0008-group-identity-name.md), where it does real work as a
  mitigation rather than being cosmetic.
- The working directory was renamed from `project-x` to `OpenBerat`.
- **Trademark search deliberately skipped.** The package, organisation and
  domain reservations do not clear a trademark, and TÜRKPATENT has no public API
  to check one automatically. This was weighed and dropped: the project is not
  being sold, and a search now would protect nothing. It becomes relevant again
  only if OpenBerat is offered commercially under that name.
- Reversing this decision later costs a crate rename, an organisation rename and
  a sweep through every document — which is why availability was verified before
  the name was adopted rather than after.
