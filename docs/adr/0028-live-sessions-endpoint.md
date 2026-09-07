# 0028 — `GET /api/admin/sessions`: the kill-switch index becomes readable

- **Status:** Accepted
- **Date:** 2026-09-07
- **Amends:** [0026](0026-audit-explain-screen-in-v1.md) — its "no new endpoint"
  consequence. The screen stays read-only, which was the load-bearing half.

## Context

[ADR-0026](0026-audit-explain-screen-in-v1.md) shipped one screen and added no
endpoint, on purpose: it drew two that already answered. The first thing asked
of that screen was the question neither of them answers — **who is connected
right now.**

The audit record cannot answer it, for two reasons that are both properties of
the design rather than gaps in it:

- **It lags.** A row is written when the decision-cache entry leaves, which is
  `cache::TTL` plus the sweep interval — measured at 35 s (`docs/07`). A list
  built from it is a list of who was active half a minute ago.
- **It misses exactly the session the product went to trouble to track.** A user
  who signs in at the portal and opens nothing has no audit row at all, and that
  is precisely the session [ADR-0019](0019-kill-switch-session-index.md) exists
  for: it was measured surviving its own kill before the index was written
  (`docs/07`).

What does know is the index ADR-0019 keeps: `openberat:sessions:<sub>`, a Redis
set of the oauth2-proxy session keys belonging to one user. `session.rs` is
explicit about what it is — *"It stores keys, not tokens: a revocation aid, not
a second session store."*

## Options

| Option | Pro | Con |
|---|---|---|
| **Read the index through a new endpoint** | Answers the real question, including the portal-only session. Nothing new is stored — the index is unchanged and stays exactly what ADR-0019 made it | A `SCAN` on an admin request, and one more route on the management plane. It can only report a `sub` and a count, because that is all the index holds |
| Derive "active" from the audit record | No new surface at all | It answers a different question and would be labelled as this one. 35 s stale, and blind to the session that never reached an application |
| Store more in the index — username, login time, source address | The list an operator actually pictures | This is the thing ADR-0019 refused to build. A second session store has to be kept correct against oauth2-proxy's, and being wrong about who is signed in is worse than not saying |
| Decrypt the oauth2-proxy session payload | Every field, from the real source | Needs the cookie secret in the backend. `session.rs` derives the key from the ticket precisely so it never touches the secret half; taking it would make the backend able to read every session's tokens to draw a table |

## Decision

**A read-only `GET /api/admin/sessions`,** on `admin::routes()` like every other
management-plane route, that scans `openberat:sessions:*` and reports, per
subject, how many of its session keys **still exist** in Redis.

The index is not changed and nothing new is written to it. The line this holds
is between *storing* session state and *reading* the state already stored:
ADR-0019 refused the first, and this is the second.

Two decisions inside it:

- **A member that no longer exists is not counted.** `forget_session` removes a
  key on logout, but a session that simply expired leaves its key in the set
  until the set's own 8-day TTL. Reporting set cardinality would report sessions
  that ended — the one wrong answer a "who is connected" list must not give.
- **The name comes from the audit record, not from the session.** The index
  holds a `sub`; the most recent `audit_event` row for that `sub` carries
  `actor_name` and a timestamp. So the column is *"last seen as"* and not
  *"username"*, and it is empty for a user who has signed in and opened nothing
  — which is honest, because that user is exactly the one nothing else knows the
  name of either.

**No kill button.** `POST /api/admin/kill/{sub}` exists and is 0.085 s, but the
screen stays read-only: nothing on it writes, so nothing on it needs an `Origin`
check, a confirmation dialogue, or a defence against a mis-click on the wrong
row. Revocation stays `INSTALL.md` §6. This is the half of ADR-0026 worth
keeping, and it is why that ADR is amended rather than superseded.

## Consequences

- **What the list can say:** the subject, how many live sessions it has, and —
  when the audit record has ever seen it — the name it was last seen under and
  when. **What it cannot say:** when the session started, from where, or through
  which browser. None of that is in the index, and the options that would put it
  there are refused above.
- **`SCAN`, not `KEYS`,** and it runs on an admin request only. This is the
  first endpoint whose cost grows with the Redis keyspace rather than with the
  answer, and that keyspace is mostly oauth2-proxy's own sessions.
  A `ponytail:` comment names the ceiling; the upgrade path, if a site ever
  measures it hurting, is a second index keyed by nothing — a set of the subs
  that have sessions — which is a write and therefore a decision to revisit.
- **Dead members are reported, not removed.** A read endpoint that pruned would
  be a write endpoint. They cost a `EXISTS` each and expire with the set.
- **`/api/admin/*` grew, and it is a supported interface** (ADR-0024, ADR-0023):
  this route is now something an upgrade has to respect.
- **The guard enumeration in `tests/integration.rs` covers it.** That list is
  the only thing standing between "the guard is a `route_layer`" and a handler
  registered somewhere else, and writing this ADR found that
  `GET /api/admin/explain` had never been added to it. Both are in it now.
