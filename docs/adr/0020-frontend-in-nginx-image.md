# 0020 — Frontend packaging: copied into the nginx image, no container of its own

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

[ADR-0005](0005-frontend-backend-split.md) gave every component its own
directory with a Dockerfile beside it, and `frontend/Dockerfile` was going to
package the static files and hand them to the nginx container through a named
volume.

That mechanism is broken by how Docker seeds volumes: an image's content is
copied into a named volume **only while the volume is empty**. The first deploy
works; every deploy after it silently serves the old files, because the volume
is no longer empty and the new image's content never reaches it. It also
contradicts the project's own packaging rule — "configuration is baked into the
image, not mounted" (CONTRIBUTING.md) — by moving the served content into a
mutable volume that outlives the image.

There is no build step to isolate ([ADR-0007](0007-frontend-buildless-static.md));
the "frontend image" would have contained nothing but files nginx serves.

## Options

| Option | Pro | Con |
|---|---|---|
| Named volume handoff (the ADR-0005 sketch) | Keeps "one Dockerfile per directory" symmetrical | Serves stale files after the first deploy; content lives in a volume, not an image |
| **`COPY frontend/src` into the nginx image** | One image serves what it ships; no volume, no extra container | nginx's build context becomes the repository root; a frontend change rebuilds the nginx image |
| Frontend as its own nginx container | Independent deploys | A second web server and an internal hop to serve five static screens |

## Decision

**The nginx image copies `frontend/src/` at build time.** In
`docker-compose.yml` the nginx service builds with the repository root as its
context so the Dockerfile can reach both `nginx/conf.d/` and `frontend/src/`.
There is no `frontend/Dockerfile`, no frontend service and no shared volume.

`frontend/` keeps its own directory and its independence as a *component* —
the `/api` contract and everything else in ADR-0005 stands. What changes is
only packaging: a directory per component, a Dockerfile per **container**, and
the frontend is not a container.

## Consequences

- One fewer image, service and volume in `docker-compose.yml`.
- A frontend change means rebuilding the nginx image. Accepted: configuration
  is baked in anyway, so nginx images are rebuilt on config changes already.
- ADR-0005's layout listing and ADR-0007's packaging consequence are amended by
  this ADR; both files carry a note. Their decisions are otherwise untouched.
- CI is unchanged — there was never a frontend build step (ADR-0007).
