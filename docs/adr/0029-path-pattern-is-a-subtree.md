# 0029 — A `path_pattern` is a subtree, and the management plane refuses any other shape

- **Status:** Accepted
- **Date:** 2026-09-07
- **Relates to:** [0009](0009-policy-engine-own-code.md) — the matcher this
  constrains the input of. `policy.rs` is not touched.

## Context

`docs/05` rule 3 says a non-empty `path_pattern` "means only that path". The
matcher does not read it that way and never has: `matches` strips a trailing
`*` and then compares at a segment boundary either way, so `/reports` and
`/reports/*` are **the same rule**. `validate_path_pattern` accepts both
without a word about it.

So `allow /reports` grants the whole `/reports/**` subtree, and the admin reads
the row back exactly as they typed it. That is the mirror image of the bug this
same function already refuses — a deny rule that can never fire — with the
sides swapped: an allow rule that grants more than it reads. Found by reading
the code against its own document, not by a failing test.

The syntax also has a hole it does not admit to: **there is no way to write an
exact path.** Every non-empty pattern is a subtree, so an admin who wants "this
one URL" has no spelling for it — and the starless form looks like one.

## Options

| Option | Pro | Con |
|---|---|---|
| A. Document the prefix semantics and leave everything | No code moves | The `*` becomes decoration that means nothing, while every table in `docs/05` writes it — the syntax keeps teaching the wrong thing, in writing |
| B. Make a starless pattern exact | Adds the one thing the syntax cannot express | **Narrows every existing starless deny rule**: `deny /admin` would stop covering `/admin/users`. A silent narrowing of a deny rule is precisely the failure this project refuses, and no reading of a stored row recovers its author's intent |
| C. Refuse to store a pattern that is not a subtree | Nothing in `policy.rs` moves, so no decision changes; the stored syntax comes to mean exactly what the matcher does; the missing feature becomes visible instead of silently mis-served | `/admin` and `/admin*` stop being accepted, and an admin who wants one exact path is told "not in v1" rather than given something that looks like it |

## Decision

**C.** The correction has to run in the direction that cannot grant anything,
and only C does: it refuses a write. B rewrites what an already-stored row
means, and the rows it would rewrite are deny rules — the one class of change
that must never happen by inference. C is also the judgement
`validate_path_pattern` already makes twice, for the same stated reason: a
pattern that would read differently from how it behaves is not stored, because
the admin believes what they read. The matcher is left alone, so every row in
every existing table keeps deciding exactly as it does today; only new writes
are constrained.

## Consequences

- A non-empty `path_pattern` **must end in `/*`**. `""` is still the whole
  application and `/*` is the same thing spelled the other way.
- `/admin` and `/admin*` are refused, with a sentence naming the form to use.
  `/admin*` is refused deliberately: it reads as a glob and behaves as a
  segment-bounded prefix, which is the same class of lie.
- **Rows already in the table are untouched** and go on behaving as prefixes.
  The schema's CHECK is *not* tightened to match: an applied migration is
  byte-immutable (`docs/07`), and a new CHECK would reject exactly those rows.
  So the schema constrains shape and the management plane constrains meaning —
  which is already the split for `slug` and `external_hostname`.
- **Exact-path matching does not exist, and now says so.** F-11 asks for
  path-based authorisation, not for exact paths. If a site needs "this URL and
  nothing under it", that is a new pattern kind, a new ADR and a change in
  `matches` — not something to be read into a missing character.
- Reversing costs one line in `validate_path_pattern`; nothing downstream
  depends on the shape.
