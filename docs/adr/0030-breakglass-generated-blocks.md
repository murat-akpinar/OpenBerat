# 0030 — Break-glass serves generated application blocks, from the same table

- **Status:** Accepted
- **Date:** 2026-09-07
- **Relates to:** [0011](0011-nginx-config-generation.md) — extends generation
  to the second configuration · [0017](0017-fail-closed-availability.md) —
  whose rehearsed way back this makes real

## Context

[ADR-0017](0017-fail-closed-availability.md) accepts a single point of failure
in front of every internal application, and what makes that acceptable is not a
promise of uptime but a **rehearsed way back**. `docs/08` is that way.

`nginx/breakglass/apps.conf` is hand-written and names two hostnames —
`sample.` and `ws.apps.example.local`, the lab's. Real applications are rows in
the `application` table and reach nginx through `conf.d/generated/apps.conf`
([ADR-0011](0011-nginx-config-generation.md)), which `breakglass.conf` does not
include. So the rehearsal passes and the procedure restores nothing: a site with
twenty applications gets twenty 404s, and finds out during the incident.

It cannot simply include the generated file. Every block in it pulls in
`protected.inc` and `decide.inc` — the authorisation break-glass exists to do
without, and both of them need a backend that is, by hypothesis, part of what is
broken.

## Options

| Option | Pro | Con |
|---|---|---|
| A. `docs/08` says the operator maintains `breakglass/apps.conf` by hand | No code at all | A second copy of the application list, maintained by hand, is stale exactly when it is read — which is the reason ADR-0011 stopped hand-writing the first one |
| B. The reload script derives break-glass blocks from the generated file by text transformation | One template to keep | The transformation *is* the removal of the authorisation includes. A change to the first template that it does not anticipate silently yields a block with `protected.inc` still in it, or one without the upstream strip. A 3 a.m. file built by `sed` from a security-relevant one |
| C. The backend renders a second file from the same table, with the same validation | Keeps the pure-function-of-the-table property ADR-0011 already rests on; one place decides what a row becomes; the two templates sit beside each other and are tested together | A second generated file to install, and `nginx-breakglass` gains a read-only mount |

## Decision

**C.** Break-glass is only worth having if it is the same list of applications,
and the only thing that keeps two lists identical is not maintaining two. The
second template is fifteen lines beside the first, validated by the same
functions and asserted by a test that reads it the way an attacker would — the
one property that matters being that no generated break-glass block may contain
`protected.inc` and no generated *normal* block may lack it.

## Consequences

- The backend writes `breakglass.apps.staged` beside `apps.conf.staged`. The
  reload loop installs it with the same test-then-keep dance, testing it with
  `nginx -t -c /etc/nginx/breakglass.conf` — the break-glass configuration
  ships in the same image, so the container that installs the file can parse it.
- **The generated name deliberately does not end in `.conf`.** `nginx.conf`
  globs `conf.d/generated/*.conf`; a break-glass block landing in the *normal*
  configuration would serve an application with no authorisation at all, on a
  running system, with `nginx -t` reporting success. That is the one mistake
  this file must be unable to make, so it is made unable by its name.
- `breakglass.conf` includes `conf.d/generated/*.apps` — a **glob**, so an
  install where the backend has never run starts and serves nothing, rather than
  refusing to start on a missing `include`.
- `nginx/breakglass/apps.conf` keeps the `:80` redirect and the default 404
  server and loses its two hand-written blocks; otherwise they collide with the
  generated blocks for the same hostnames.
- `nginx-breakglass` mounts the `apps_conf` volume **read-only**. ADR-0017's
  `edge`-only network rule stands untouched: this is a file, not a network path,
  and the file is derived state written before the incident rather than during
  it.
- The rehearsal in `docs/08` now proves something. It did not before: it
  exercised the two hostnames that were in the file either way.
- Reversing costs the second template and the mount, and puts the hand-written
  blocks back.
