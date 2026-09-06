# Contributing to OpenBerat

OpenBerat is free software you install and run yourself. Patches are welcome.

## Sign off your commits (DCO)

Every commit needs a `Signed-off-by` line. Git adds it for you:

```
git commit -s -m "your message"
```

By signing off you affirm the [Developer Certificate of Origin
1.1](https://developercertificate.org/): the contribution is yours to submit, and
you understand it is contributed under the project's licence.

There is no CLA to sign — you keep the copyright on what you write. A pull
request without a sign-off is not merged ([ADR-0018](docs/adr/0018-contributions-dco.md)).

## Write conventional commits

The changelog is generated from commit messages with
[git-cliff](https://git-cliff.org), so the subject line has to follow
[Conventional Commits](https://www.conventionalcommits.org):
`type(scope): a lowercase sentence`. A commit that does not parse is dropped
from the changelog silently.

If the body explains something, put the explanation in the **first paragraph** —
that is the part that ends up in `CHANGELOG.md`.

## Found a vulnerability?

Do not open a public issue. [SECURITY.md](SECURITY.md) has the reporting
channels, the response times and what is in scope — there is no released version
yet, so the useful report at this stage is a flaw in the design itself.

## Licence

OpenBerat is [GPL-3.0-or-later](LICENSE). Contributions are accepted under the
same terms ([ADR-0013](docs/adr/0013-licence-gpl.md)).

## Before you write code

- Read [`docs/adr/`](docs/adr/). Most "why is it done this way" questions are
  answered there, including the ones where the answer is "this is accepted debt".
- [`docs/06-requirements.md`](docs/06-requirements.md) holds what is still
  undecided. If your change touches one of those, say so in the pull request.
- The rules below are the ones the design documents treat as settled. The two
  that catch people out: documentation and code comments are English, and
  anything deciding identity, session or authorisation needs a test that was
  seen to fail first.

## The rules the documents cite

The design documents refer to these as settled project rules. They are here so a
reader outside the maintainer's machine can find them.

- **Fail-closed.** If an authorisation decision cannot be made, the answer is
  deny. This applies to the system as a whole, not only to `policy.rs`
  ([ADR-0017](docs/adr/0017-fail-closed-availability.md)).
- **Configuration is baked into the image, not bind-mounted**, so a running
  system cannot drift. Two exceptions: the nginx application blocks generated
  from the database ([ADR-0011](docs/adr/0011-nginx-config-generation.md)), and
  `keycloak/realm/`, which is **import data** — read once into Keycloak's own
  database at boot, not configuration a running system serves from. The test is
  whether it is read at runtime; if it is, it belongs in the image. A Keycloak
  login theme is read at runtime, so it is not covered by this exception.
- **The audit record format is immutable.** Changing what an `audit_event` row
  holds is a breaking change, which is why the summary columns are in the first
  migration rather than added later (`docs/02-architecture.md`).
- **`policy.rs` stays pure:** no database, no HTTP, no reading the clock. Every
  input arrives as a parameter, so the decision is testable in isolation. It is
  the file with the strictest test requirement in the repository.
- **Nothing speculative.** No column, config value, or abstraction with one
  implementation added because it might be needed later.
- **Documentation and code comments are English**, `README_TR.md` excepted.
  Comments say *why*, not *what*.

## What gets rejected

- An authorisation decision made anywhere but the backend. The frontend
  displays; it never decides.
- A change to the `/api` contract without the table in
  [`docs/02-architecture.md`](docs/02-architecture.md) updated in the same commit.
- New dependencies where a few lines would do, or abstractions with a single
  implementation.
- Anything that fails open. If an authorisation decision cannot be made, the
  answer is deny.
- A change to a security boundary tested only on the happy path. Show the attack
  being refused — a forged header, a double-encoded path, an expired grant — not
  just the ordinary request being allowed.
- A test that was never seen to fail. If it passes against the unfixed code, it
  is not testing the fix.
