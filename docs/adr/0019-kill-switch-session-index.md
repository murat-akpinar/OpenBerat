# 0019 — The kill switch needs a `sub → session` index

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

[ADR-0016](0016-n03-revocation-targets.md) promises the kill switch acts in
**≤ 5 seconds**, and [ADR-0003](0003-oidc-oauth2-proxy.md) says it acts in two
places: Keycloak `logout-all` **and** deleting the oauth2-proxy session from
Redis. `docs/04` and `docs/05` repeat the second step as if it were free.

It is not. **Nothing in the design can find that session.**

oauth2-proxy's Redis store is keyed by a ticket derived from the session cookie,
not by the user. There is no `sub` in the key, and oauth2-proxy exposes no
"terminate this user's sessions" API. The backend's own cache does not help
either: its key holds `cookie_hash`, a SHA-256, and a hash cannot be turned back
into the cookie the ticket is derived from (`docs/05`, "Decision cache").

Without the Redis step the kill switch degrades to Keycloak `logout-all` plus
waiting for the session to notice — that is `cookie_refresh`, i.e. **5 minutes,
not 5 seconds.** The N-03 kill-switch target would be a false claim.

## Options

| Option | Pro | Con |
|---|---|---|
| **A — the backend keeps a `sub → session key` index** | The backend already holds the raw `Cookie` on every cache miss, which is the only moment the session key is derivable | The backend gains a Redis dependency; the index is state the backend has to expire |
| B — scan and decrypt Redis on kill | No index to maintain | `SCAN` over every session, decrypting each to find one user; O(sessions) under incident response, and it needs oauth2-proxy's cookie secret |
| C — drop the Redis step, rely on Keycloak `logout-all` | Nothing to build | The kill switch becomes `cookie_refresh`-bound: N-03's 5 s target is withdrawn |
| D — shorten `cookie_refresh` until C is fast enough | Nothing to build | A 5 s refresh means a token exchange with Keycloak on every request-ish; it moves the cost onto the IdP and still misses (ADR-0016) |

## Decision

**A.** On a decision-cache miss the backend already forwards the raw cookie to
oauth2-proxy and learns `sub`; at that point it also records the session key
derived from that cookie into a `sub → {session key}` index. The kill switch
deletes those keys from Redis directly, then drops the user's decision-cache
entries (order below). The index lives in the same Redis oauth2-proxy already
requires, so no new component appears — only a new connection.

The derivation of the Redis key from the cookie value is a **claim about
oauth2-proxy's internals, and it is not verified.** It is written into
`docs/07`'s unverified list and measured in Phase 1, before any code depends on
it. If the derivation does not hold, the fallback is **C**, and ADR-0016's 5 s
target is revised rather than quietly missed.

## Consequences

- **The backend now connects to Redis**, not only Postgres. `docs/02`
  (components, deployment) and the README diagrams say so.
- The kill switch order is fixed and now has four steps:
  **Keycloak `logout-all` → the session keys from the index → the decision cache
  entries for that `sub` → the index entry itself.** Reversing any pair lets a
  request arriving in the gap refill what was just cleared.
- Only that user's cache entries are dropped, never the whole cache — clearing
  it for everybody is self-DoS (`docs/05`).
- The index is bounded and expires with the session; a `sub` that never signs in
  again leaves nothing behind. It carries session keys, not tokens or groups: it
  is a revocation aid, not a second session store.
- **Phase 1 gains a verification** (`TODO.md`, VERIFY 4). If it fails, this ADR
  is superseded and ADR-0016 is revised in the same commit.
- Reversing this later costs little: option C is what remains if the index is
  deleted, at the price of the 5 s promise.
