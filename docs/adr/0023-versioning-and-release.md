# 0023 — One version for the whole product, and the release is a bundle

- **Status:** Accepted
- **Date:** 2026-09-07

## Context

Phase 6 asks for three things that look separate and are not: a version number,
a release image, and an offline bundle for a site with no internet.

The third one decides the other two. **An air-gapped site cannot build this
product.** `backend/Dockerfile` compiles Rust against crates.io, the nginx and
Keycloak images install packages, and the Keycloak base image resolves Maven
artifacts on its first start. So whatever a release *is*, it has to contain
images that are already built — and once the artifact is a set of images, "the
version" is a property of that set and not of one crate.

There is a second reason the set is the unit. The pieces do not have independent
contracts: the `/decide` header contract is written by the nginx include and
read by the backend (`docs/02`), the generated application blocks are rendered
by the backend into a volume nginx serves (ADR-0011), and the frontend is inside
the nginx image (ADR-0020). A bug report naming "backend 0.3" would not say
which nginx configuration it ran behind, which is the half that decides whether
a header was stripped.

## Options

### What a version counts

| Option | Pro | Con |
|---|---|---|
| **A — a version per component** | Each moves when it changes | Three numbers for one deployment, and the contracts run *between* the components. The operator runs a set; the set is what a report has to name |
| **B — one semver for the product** | One number, on every image and in the startup log. Says something about upgrading | Somebody has to decide what counts as breaking, in a product with no public API |
| **C — CalVer (`2026.09`)** | No judgement call, and it dates the artifact | Says nothing about compatibility — and this product has a compatibility surface that bites: the audit row format is immutable by rule (`CONTRIBUTING.md`), migrations are forward-only, and the older binary refuses to start against a newer schema (`INSTALL.md` §9) |

### What a release is

| Option | Pro | Con |
|---|---|---|
| **D — a registry (ghcr.io) and nothing else** | `docker compose pull`, familiar | Does not reach an air-gapped site at all, and adds an account, a signing story and a mirror step before the first install works |
| **E — source tag only** | Nothing to host | Every installation compiles Rust and resolves Maven. That is the case that cannot work offline, and it makes the install time and the install's dependencies unbounded |
| **F — one tarball: the tagged source plus every image, saved** | The only artifact that installs with no network; it is also what a registry would need pushed, so it does not become dead work | Large (hundreds of MB), and it freezes the third-party images at whatever their tags resolved to on the build host |

## Decision

**B and F.**

One semantic version for the whole product, defined in exactly one place —
`version` in `backend/Cargo.toml`. It reaches the running system through
`env!("CARGO_PKG_VERSION")`: the backend logs it at startup and publishes it as
`openberat_build_info{version="…"}` on `/metrics`, so "which version is this"
has an answer from inside a running deployment and not only from a filename.

What the parts mean here, since there is no public API to break:

| Part | Changes when |
|---|---|
| MAJOR | the operator must do something before upgrading: an environment variable removed or renamed, the `audit_event` row format changed, the `/decide` header contract changed, or `ADMIN_GROUP` semantics changed |
| MINOR | a capability arrives and the existing configuration keeps working |
| PATCH | fixes only, no new configuration |

The release artifact is **one tarball**, produced by `release.sh`: `git archive`
of the tag, plus `docker save` of every image the release compose references. It
is both "the release image" and "the offline bundle" because building two
artifacts would mean testing two, and the one that installs offline is a
superset of the one that does not.

No registry in this release. When one is wanted, the same script already
computes the list of images to push, so it is an addition rather than a rewrite.

## Consequences

- **The lab leaves the default compose.** `samba-ad`, `sample-app` and
  `sample-ws` move behind `profiles: [lab]`. A release that starts a domain
  controller and two echo servers on an operator's host is not a release —
  ADR-0010 already said the Samba DC ships in nothing, and until now only the
  order of arguments in `INSTALL.md` §5 was keeping that true.
- **A bundle is reproducible only as far as the third-party tags are.**
  `postgres:17-alpine`, `redis:7-alpine`, `quay.io/oauth2-proxy:v7.8.2` and the
  Keycloak base are pinned by tag, not digest, so two bundles built a month
  apart can differ. The bundle itself freezes them by content, which is what the
  air-gapped site actually receives — the drift is between bundles, not inside
  one.
- **`docker compose up` must not silently build on the target.** The images are
  loaded before the first `up`; if one is missing, the fix is a complete bundle,
  not a build on a host that was never meant to compile anything.
  `INSTALL.md` §11 uses `--pull never` so that a missing image is an error
  rather than a download.
- **Upgrading is still restoring, if it goes wrong.** Migrations are forward
  only and the previous binary will not start against the newer schema, so a
  version number does not buy a rollback — the dump taken before the upgrade
  does (`INSTALL.md` §9). MAJOR is a warning, not a safety net.
- The tag is signed and pushed by the maintainer; nothing in CI creates one. A
  release that a script can cut by itself is a release that can be cut by
  accident.
