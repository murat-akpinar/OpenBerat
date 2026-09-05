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

## Licence

OpenBerat is [GPL-3.0-or-later](LICENSE). Contributions are accepted under the
same terms ([ADR-0013](docs/adr/0013-licence-gpl.md)).

## Before you write code

- Read [`docs/adr/`](docs/adr/). Most "why is it done this way" questions are
  answered there, including the ones where the answer is "this is accepted debt".
- [`docs/06-requirements.md`](docs/06-requirements.md) holds what is still
  undecided. If your change touches one of those, say so in the pull request.
- [`CLAUDE.md`](CLAUDE.md) holds the code and documentation conventions. Two that
  catch people out: documentation is English (`README_TR.md` is the one
  exception), and anything that makes an identity, session or authorisation
  decision needs a test.

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
