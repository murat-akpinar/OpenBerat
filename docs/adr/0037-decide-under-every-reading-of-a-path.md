# 0037 — A path is decided under every reading an upstream might give it

- **Status:** Accepted
- **Date:** 2026-10-10
- **Relates to:** [0009](0009-policy-engine-own-code.md) — the matcher whose
  input this changes; [0029](0029-path-pattern-is-a-subtree.md) — what a
  pattern means, which this does not touch. Answers the `docs/06` question
  "Do the protected applications strip path parameters?"

## Context

`policy::normalise` turned `X-Original-URI` into one path: decode once, fold
`\` into `/`, resolve `.` and `..`, lower-case. Every row of the `docs/05`
"Path normalisation" table is a deny rule that this protects — `/%61dmin/`,
`/x/../admin/`, `/x\..\admin/` and `/admin%2fusers` all land on `/admin/`.

Security audit run-1 (2026-10-10) showed the other side of the same choice.
Decoding before resolving is one upstream's reading, not every upstream's:

| Request | `normalise` | An upstream that resolves first and decodes a segment as data | Tomcat / Jetty (drop `;params`) |
|---|---|---|---|
| `/admin/..%2Fpublic/x` | `/public/x` | under `/admin/` | under `/admin/` |
| `/admin/x\..\..\public/y` | `/public/y` | under `/admin/` | under `/admin/` |
| `/public/..;/admin/` | `/public/..;/admin/` | same | `/admin/` |
| `/admin;x/users` | segment `admin;x` | same | `/admin/users` |
| `/admin/secret#/../../public/` | `/public/` | cut at `#`: `/admin/secret` | — |

With only `allow /public/*` granted, the first three were **allowed** by the PDP
(reproduced as unit tests) and served from `/admin/` by an upstream that reads
them its own way. The fourth is the open `docs/06` question: a deny on
`/admin/*` that a Java upstream walks past. Which reading is right depends on
what runs behind the proxy — and the PEP does not know.

## Options

| Option | Pro | Con |
|---|---|---|
| A. Keep one reading | Nothing changes | The allow side stays escapable on every upstream that reads differently |
| B. Refuse `\`, `%2F`, `%5C`, `;` and `#` outright (`malformed_uri`) | Smallest code | Breaks applications that use them legitimately: Jenkins multibranch jobs carry `%2F`, Java stacks put `;jsessionid` in URLs |
| C. A per-application parser setting | Exact for each upstream | A column and an admin choice nobody can make correctly without reading the upstream's source; a wrong guess is a bypass |
| D. **Decide under every reading; pass only if every one passes** | Fail-closed whatever the upstream does; legitimate paths read the same under all three, so they are unaffected | A path that one reading denies is denied even if the real upstream would have read it the safe way |

## Decision

**D**, plus refusing a raw `#` (no browser sends one; the only use is the attack).
`decide` computes three paths — the decoded one `normalise` has always produced,
the path resolved on the raw bytes and then decoded, and the raw path with every
segment's `;params` dropped, resolved, then decoded — and evaluates the rules
against each. An explicit deny under any reading answers `explicit_deny`; any
other denial answers with its own reason; only three allows make an allow. It
costs two more string passes per miss, which the decision cache hides.

## Consequences

- The `docs/06` path-parameter question is closed: `/admin;x/` meets a
  `/admin/*` deny on every application, Java or not. The "carry deny rules one
  segment higher" advice is withdrawn.
- Over-denial is possible and accepted: a non-Java application whose deny rule
  names `/a/*` also refuses `/a;b/c`. A grant written for a segment that itself
  contains `;` cannot be honoured — no such application is known.
- `explain` takes its verdict from `decide`, so it shows the combined answer; its
  per-rule `matched` column still reads the decoded path only.
- `normalise` stays as it was (plus `#`) — `validate_path_pattern` uses it to
  check a stored pattern, and patterns carry no encoding.
- Reversing it is deleting `readings` and calling `normalise` again; nothing is
  stored differently.
