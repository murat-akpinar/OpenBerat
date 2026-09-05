# Architecture Decision Records

Every significant technical decision gets a file here. Filename:
`NNNN-short-title.md`.

Written **after** the decision is made, not during the discussion. Changing a
decision does not mean deleting the old file — it means writing a new one and
marking the old one `Superseded`.

Template: `0000-template.md`

Every decision the design could settle on its own has an ADR; what remains open
needs facts about the target environment and lives in `docs/06-requirements.md`.
`0019` is the exception: it settles a design question but rests on a claim about
oauth2-proxy that Phase 1 has to confirm (`docs/07`, "Unverified").
