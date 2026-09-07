# 0031 — The decision cache with more than one instance: broadcast invalidation, not a shared cache

- **Status:** Accepted
- **Date:** 2026-09-07
- **Relates to:** [0016](0016-n03-revocation-targets.md) — the 5 s target this
  protects. [0019](0019-kill-switch-session-index.md) — the Redis the broadcast
  reuses. [0017](0017-fail-closed-availability.md) — the single point of failure
  a shared cache would move rather than remove.

## Context

N-06 puts HA outside v1 and adds "the design will not prevent it". `TODO.md`'s
HA box cannot open before this one, because one part of the design does prevent
it.

The decision cache is instance-local: a map keyed `(cookie_hash, app_slug)` in
`cache.rs`, TTL 30 s, with a `sub → keys` reverse index so logout and the kill
switch drop one user's entries rather than everybody's. The kill switch has four
fixed steps (ADR-0019), and with two instances **three of them are already
fleet-wide**: Keycloak `logout-all` is global, and the oauth2-proxy session keys
and the index itself live in the shared Redis. Only step 3 — this user's cache
entries — happens in one process.

So the failure is narrow and exact. The instance that answered the admin's POST
drops its entries; every other instance keeps answering ALLOW from its own copy
until the entry expires. **The kill switch degrades from a measured 0.085 s to a
full TTL, 30 s** (`docs/07`), against ADR-0016's 5 s. Logout has the same shape.

Two things this is *not* about, so they do not have to be defended below. The
AD-change path is untouched: the TTL bounds every instance independently, so the
330 s ceiling holds whatever the instance count. And nothing else in the cache is
cross-instance — entries are derived, never authoritative, so two instances
disagreeing costs a miss, not a wrong answer.

## Options

Both round trips below were measured on the lab, from a container on the same
compose network a second backend instance would sit on (`docs/07`).

| Option | Pro | Con |
|---|---|---|
| **A. The cache itself moves to Redis** | One copy, so an invalidation is a `DEL` and there is nothing to broadcast; no new failure mode to reason about | A round trip on **every** decision: measured `GET` of a 600-byte entry at **p50 0.039 ms** on one connection and **0.167 ms** at sixteen. That fits N-01's 2 ms — and it is 1.5–6× the **entire** measured cost of a decision today (11–29 µs), on each of the 50 asset requests a page makes. It also breaks the audit design: the entry carries the counters and the entry is the flush unit (`docs/02`, "Audit granularity"), so a shared entry means either a read-modify-write per request or counters no eviction ever writes. And it makes Redis a synchronous dependency of every decision rather than of the miss path — HA that moves the single point of failure instead of removing it |
| **B. The cache stays local; invalidation is broadcast** | The cache stays a hash lookup, so N-01 and the audit design are untouched; Redis is already a dependency (ADR-0019) and no component appears; measured **281–288 µs** from publish to delivery at an already-connected subscriber, four orders of magnitude inside the 5 s target | A subscriber that has quietly lost its connection goes on serving stale ALLOWs and nothing says so. That has to be answered, and it is, below |
| **C. Bound the damage with a shorter TTL** | No mechanism at all | To bound staleness under 5 s the TTL must *be* about 5 s, which spends the whole budget and leaves none for the other three steps. It multiplies misses roughly sixfold, and a miss is 2.7–4.7 ms with an oauth2-proxy hop, a Redis write and a Postgres query in it against 11–29 µs for a hit (`docs/07`) — paid by every session, on every instance, to buy the AD path a change from 330 s to 305 s that nobody asked for |
| **D. Sticky routing on the session cookie** | `hash $cookie__oauth2_proxy consistent` is in nginx OSS (`sticky` is Plus), and it keeps one session's entries on one instance — no duplication, no cold second copy | **It does not solve this.** A `sub` has several sessions, they hash to different instances, and the admin's own POST lands wherever nginx puts it. Complementary, not an answer |

Rejected without a row: fanning the invalidation out over HTTP to each instance.
It needs an instance registry, which is the thing Redis pub/sub already is.

## Decision

**B.** A is the only option that removes the problem instead of answering it,
and the measurement is why it still loses: the round trip is affordable against
the *target* and unaffordable against the *system*, which spends 11–29 µs on a
decision and about 1% of a request on deciding it. Paying 39–167 µs on every
asset of every page to fix a 30 s window that opens only on a kill switch is the
wrong end of the trade, and it drags the audit summarisation and a new
whole-fleet dependency along with it. C pays a permanent tax for a partial fix.
D fixes a different problem. B leaves the hot path exactly as it is measured and
puts the cost on the one path that is allowed to be slow — the kill switch,
which has a 5 s budget and spends 0.085 s of it.

## Consequences

- **One channel, `openberat:invalidate`, carrying a `sub`.** Every instance
  calls the `drop_sub` the kill switch and logout already call, so the road out
  of the cache is unchanged and every dropped entry still flushes its counters
  to the audit channel — on the instance that held them.
- **The four-step order stands** (ADR-0019). Step 3 becomes "publish, then drop
  locally"; nothing moves in front of Keycloak `logout-all`.
- **An instance with no live subscription serves no cache hits.** This is the
  half that makes B safe rather than merely fast: a lost subscription turns
  every request into a miss — an oauth2-proxy hop and a query, N-02 latency —
  and never into a stale ALLOW. It is one flag read in `get`, and it is the
  fail-closed direction the rest of the product already runs in.
- `PUBLISH` returns how many subscribers it delivered to. **That is not an
  acknowledgement from an instance's cache and is not treated as one.** With the
  rule above it is enough: an instance either holds a live subscription and was
  sent the message, or holds none and is answering nothing from cache.
- **The residual gap is named, not designed away:** a connection alive at TCP
  level while the instance's reader is wedged. Nothing here bounds it. The HA
  box either adds a heartbeat that fails the flag, or writes the gap into
  `docs/07` — it does not get to leave it unmentioned.
- Broadcasting a **logout** drops that user's entries for their *other* sessions
  too, on every instance. Those sessions are still valid; the cost is a miss
  each, and the alternative — broadcasting a key — would need the killer to know
  a cookie it does not hold.
- **Entries stay per-instance,** so N instances hold N copies and each pays its
  own first miss. Option D above removes most of that and is recommended
  alongside this, not instead of it.
- **Nothing changes while there is one instance.** Publishing to oneself is the
  `drop_sub` the code performs today, so the mechanism is inert until a second
  instance exists — which is exactly why it can be decided now and built with
  the HA box rather than before it.
- Two sentences elsewhere said A and are corrected in the same commit: `docs/05`'s
  `ponytail:` line ("Move to Redis once there are several") and `docs/02`'s
  availability row ("moves to Redis with multiple instances").
- Reversing costs the subscriber task and the flag. A stays available if a later
  measurement finds the duplication costs more than the round trip — the entries
  are derived data, so nothing has to be migrated to change one's mind.
