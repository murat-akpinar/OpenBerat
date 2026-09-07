# 0025 — `worker_shutdown_timeout`: bound the worker, not the connection

- **Status:** Accepted
- **Date:** 2026-09-07

## Context

[ADR-0011](0011-nginx-config-generation.md) reloads nginx every time an admin
changes an application. A reload does not close connections that are already
open: the old worker goes to `worker process is shutting down` and keeps serving
them, under the **old** configuration, until the last one closes. For an HTTP
request that is milliseconds. For an upgraded WebSocket or SSE connection it is
unbounded, because `worker_shutdown_timeout` is unset and nginx's default is no
timeout at all.

Both halves are measured (`docs/07`). In Phase 1 the same worker PID was still
shutting down 133 s after a reload with a live connection on it; re-measured for
this decision, a worker retired by one reload was still there **102 s later**
and its connection was still trading frames. Two things follow, and only one of
them is new:

- **A policy change does not reach a connection that is already up.**
  [ADR-0016](0016-n03-revocation-targets.md) already states this and excludes
  upgraded connections from N-03. Nothing here changes that.
- **The worker count is unbounded.** One worker accumulates per reload for as
  long as any long-lived connection is open. An admin adding ten applications
  while one user has a WebSocket open leaves ten workers behind, each holding
  its own `worker_connections` and its own copy of the configuration it was
  started with. That is a resource leak driven by ordinary admin activity, and
  [ADR-0017](0017-fail-closed-availability.md) accepts a single point of
  failure — which makes an nginx that grows without bound exactly the failure
  it cannot also accept.

The reason this is an ADR and not a one-line config change is that the
directive does not only bound the leak: it bounds **every** reload, including
ordinary ones, by killing whatever is still in flight when the timer expires.

## Options

| Option | Pro | Con |
|---|---|---|
| **A — leave it unset** | A reload never cuts anything. Whatever was in flight finishes, however long it takes | The leak stays. The only bound on the worker count is how often an admin edits applications, and the only thing that clears it is a restart — which is an outage, not a mechanism (`docs/07`) |
| **B — set it, no other change** | The worker is bounded, so the leak is. Costs one directive and reaches the case that produces it | Anything still in flight when the timer expires is cut. The value has to be large enough not to punish a legitimate slow request |
| **C — set it *and* reload periodically** | Every upgraded connection is bounded, not only the ones a reload happens to catch — the route `docs/02` names as the next step if the gap matters | It would not deliver N-03 anyway (below), and it cuts every connection on a schedule for no policy gain. `docs/02` calls it a blunt instrument; the arithmetic agrees |

**C is where the tempting mistake is.** A reload every 300 s looks like it turns
ADR-0016's exclusion into a 300 s revocation bound. It does not: the client
reconnects into an oauth2-proxy session that can still be 330 s stale
(`cookie_refresh` + cache TTL, ADR-0016), so the worst case is the two in
series — near 630 s, not 360 s. Reload churn on every application, every five
minutes, forever, and N-03's six minutes still would not hold for upgraded
connections.

## Decision

**`worker_shutdown_timeout 300s`, in `nginx.conf` and in `breakglass.conf`. No
periodic reload. The N-03 exclusion for upgraded connections stands.**

300 s is not a new number: it is `proxy_read_timeout` on protected locations
(ADR-0016, `nginx/conf.d/README.md` rule 11), the longest this proxy already
lets a connection sit. Setting the two to the same value means a reload cuts
nothing sooner than the configuration already permitted it to be cut, and there
is one duration to remember instead of two.

The directive is main-context, so it cannot live in a shared include the way
`tls.inc` and `security.inc` do — it is written twice. CI checks that both files
carry it and that they agree, which is the same protection the include gives the
http-level settings.

## Consequences

- **The leak is bounded, and the bound was measured.** A worker started under
  this configuration and retired by a reload exited **302 s** later and took its
  WebSocket with it (`docs/07`). The worker count is therefore bounded by how
  many reloads land in a 300 s window, and ADR-0011's 2 s debounce bounds that
  in turn.
- **Setting it does not reach a worker that is already shutting down.** The
  timer comes from the configuration the worker was *started* with, not the one
  live when it is retired: measured, with the value set to 20 s and reloaded
  twice, the worker retired under the unset configuration was still shutting
  down 102 s later while a worker started under the new value died at 20 s. So
  the first reload after this change still leaves one unbounded worker behind,
  and on a system that already has some, they stay until their connections
  close. `docker compose up -d nginx` clears them; a reload does not.
- **Anything still in flight 300 s after a reload is cut.** That is the price,
  and it is the point. Ordinary traffic does not notice: 120 requests spanning
  two reloads with the value set all answered, none failed (`docs/07`). A
  request that legitimately runs longer than 300 s through this proxy — a large
  upload, a slow export — would be cut if a reload happened to fall under it.
- **Reversal trigger.** If an application needs a request longer than 300 s,
  the value is raised *together with* `proxy_read_timeout`, not instead of it:
  they are one number on purpose, and letting them drift would mean an idle
  connection outliving a reloaded one or the reverse, with nothing written down
  saying which.
- **Break-glass carries it too.** It is reloaded by hand rather than by
  ADR-0011, so it leaks more slowly — but an incident configuration is the last
  place to discover a difference between two files that otherwise say the same
  thing.
- ADR-0016's last consequence and `nginx/conf.d/README.md` rule 18 both said
  this was open. They now say what it is set to and what that does and does not
  buy.
