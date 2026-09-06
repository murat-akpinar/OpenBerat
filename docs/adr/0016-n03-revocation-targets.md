# 0016 — N-03: revocation delay targets

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

N-03 has been an unanswered "?" in `docs/06` while three other values were
derived from it: `cookie_refresh`, the decision cache TTL and
`proxy_read_timeout`. Phase 2 and Phase 3 cannot be written against an unknown
number.

The design already fixes what is achievable. ADR-0006 established that staleness
lives in exactly one place, the oauth2-proxy session, and that the delay is
`cookie_refresh + cache TTL` — two numbers, currently 5 minutes and 30 seconds.
Setting N-03 is therefore mostly a matter of stating what the design delivers,
with margin, and being explicit about what it does **not** cover.

## Decision

| Path | Target | Where it comes from |
|---|---|---|
| Disabled in AD, or removed from a group | **≤ 6 minutes** | `cookie_refresh` 5 m + cache TTL 30 s + margin |
| Kill switch (incident response) | **≤ 5 seconds** | Four synchronous steps, no TTL involved (`docs/05`, [ADR-0019](0019-kill-switch-session-index.md)) |
| Logout initiated by the user | **≤ 5 seconds** | The same steps, with the browser in hand (`docs/02`, "Logout") |
| WebSocket/SSE connection already upgraded, idle or active | **Excluded from the guarantee** | See below |

Six minutes is the product's promise for the ordinary path: an account disabled
in AD loses access within six minutes without anyone intervening. That is
already better than the VPN it replaces, and the kill switch exists for when
six minutes is not good enough.

## The exclusion, stated plainly

An **active** WebSocket or SSE connection is authorised once, at the upgrade,
and is not re-authorised afterwards. `proxy_read_timeout` is an idle timeout and
does not bound a connection carrying steady traffic (`docs/02`, "Long-lived
connections"). No value of N-03 changes this. An **idle** one is cut, at 300 s —
but cut is not revoked, and the reconnect that follows re-enters the ordinary
staleness, which is why the row above excludes it too (see the consequences).

So the guarantee is: **the targets above apply to HTTP requests. A connection
already upgraded is outside them.** Publishing a "6 minutes" number while a
WebSocket stays open indefinitely would be a false claim, and this is the kind of
gap a security review finds.

`proxy_read_timeout` is still set to 300 s on protected locations — it cuts idle
connections, which is worth having and costs nothing. **Measured** (`docs/07`):
on one vhost, one timeout and one cookie, the silent connection died at
t+300.002 s and the talking one was still trading frames at t+420 s.

## Consequences

- **The 5 s target rests on [ADR-0019](0019-kill-switch-session-index.md).**
  Without a `sub → session` index there is no way to find the user's
  oauth2-proxy session, and the kill switch degrades to `cookie_refresh` —
  5 minutes. That ADR rests in turn on a Phase 1 verification; if it fails, the
  kill-switch row above is revised in the same commit rather than left standing.
- `cookie_refresh = 5m` and cache TTL = 30 s are now **derived values**, not
  preferences. Raising either requires revisiting this ADR.
- `proxy_read_timeout 300s` on protected locations.
- Phase 1 measures both paths against these targets, and Phase 6 repeats the
  measurement as an exit criterion. If the measured value exceeds the target,
  the lever is `cookie_refresh` — at the cost of more token refresh traffic to
  Keycloak. **The Phase 6 repeat is done and the target holds** (`docs/07`):
  the ceiling is still 330 s, and the cut still lands at the same session age
  it did in Phase 1, to within 0.6 s, through a chain that gained the
  kill switch's index write on exactly the request that performs the refresh.
- **The six-minute row is measured** (`docs/07`): a group removed in AD cut a
  polling client **283 s** later — an experiment-dependent figure, as the Phase 6
  repeat showed, because the cut lands at a fixed session age and the delay from
  the change moves with how late the change fell after the session was minted —
  and the `cookie_refresh` + cache TTL ceiling of **330 s**, which does not
  move, was reached deliberately, by minting a cache entry four seconds before
  the refresh boundary — sixteen requests answered 200 past a boundary the
  session had already crossed. Inside the target, with 30 s of margin and
  no term left to absorb anything slower. It also corrects the lever named
  above: the two terms are not sequential delays, because a cache hit never
  reaches oauth2-proxy at all, and shaving the **cache TTL** buys the same
  seconds for a subrequest and a query rather than for a token refresh against
  Keycloak.
- The WebSocket exclusion is a **documented product limitation**, and it belongs
  in the installation documentation, not only here. An application whose
  security depends on immediate revocation should not be exposed over a
  long-lived connection behind this proxy.
- The Phase 1 WebSocket measurement is no longer a curiosity; it quantifies a
  stated limitation. **Measured** (`docs/07`): an active connection carried 500
  exchanges over 499 s, 489 s of them after the group was removed, while the
  HTTP path on the same cookie was cut at the `cookie_refresh` boundary. Neither
  the kill switch nor `nginx -s reload` reached it — the connection ran 195 s
  with no session in Redis at all. The exclusion above is the measured
  behaviour, not a cautious guess.
- **An idle connection is bounded, not revoked, and the bound is not six
  minutes.** The idle timer and the session's staleness run side by side, not in
  series: a connection cut at 300 s reconnects into a session that can still be
  330 s stale, and that reconnect is another 300 s of connection. Arithmetic on
  top of two measurements rather than a third measurement, but it puts the worst
  case near 630 s — which is why the exclusion above is written as *every*
  upgraded connection and not only the busy ones.
- **A reload is not a revocation, and it is not free either.** ADR-0011
  regenerates the application blocks and reloads nginx; each reload leaves one
  worker in `shutting down`, serving the old configuration, for as long as a
  long-lived connection stays open. `worker_shutdown_timeout` would bound both —
  it is the only lever measured to work short of a restart — and it is an open
  question in `docs/06` because it also bounds ordinary reloads.
