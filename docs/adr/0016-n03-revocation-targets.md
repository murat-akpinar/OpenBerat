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
| Kill switch (incident response) | **≤ 5 seconds** | Three synchronous steps, no TTL involved (`docs/05`) |
| Logout initiated by the user | **≤ 5 seconds** | The same three steps (`docs/02`, "Logout") |
| Active WebSocket/SSE connection | **Excluded from the guarantee** | See below |

Six minutes is the product's promise for the ordinary path: an account disabled
in AD loses access within six minutes without anyone intervening. That is
already better than the VPN it replaces, and the kill switch exists for when
six minutes is not good enough.

## The exclusion, stated plainly

An **active** WebSocket or SSE connection is authorised once, at the upgrade,
and is not re-authorised afterwards. `proxy_read_timeout` is an idle timeout and
does not bound a connection carrying steady traffic (`docs/02`, "Long-lived
connections"). No value of N-03 changes this.

So the guarantee is: **the targets above apply to HTTP requests. A connection
already upgraded is outside them.** Publishing a "6 minutes" number while a
WebSocket stays open indefinitely would be a false claim, and this is the kind of
gap a security review finds.

`proxy_read_timeout` is still set to 300 s on protected locations — it cuts idle
connections, which is worth having and costs nothing.

## Consequences

- `cookie_refresh = 5m` and cache TTL = 30 s are now **derived values**, not
  preferences. Raising either requires revisiting this ADR.
- `proxy_read_timeout 300s` on protected locations.
- Phase 1 measures both paths against these targets, and Phase 6 repeats the
  measurement as an exit criterion. If the measured value exceeds the target,
  the lever is `cookie_refresh` — at the cost of more token refresh traffic to
  Keycloak.
- The WebSocket exclusion is a **documented product limitation**, and it belongs
  in the installation documentation, not only here. An application whose
  security depends on immediate revocation should not be exposed over a
  long-lived connection behind this proxy.
- The Phase 1 WebSocket measurement is no longer a curiosity; it quantifies a
  stated limitation.
