# 0004 — Implementation language: Rust

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

Which language will the service we write (PDP + portal + admin) be in?

The first proposal was **Go**, on the grounds that every reference project in
this space (Pomerium, Teleport, oauth2-proxy, Authelia, Caddy) is Go.

## Options

| Option | Pro | Con |
|---|---|---|
| Rust | The language the team actually writes; axum/tower/sqlx are mature; small static binary | The reference code in this space is Go; the OIDC crates are less battle-worn than `go-oidc` |
| Go | The reference language of the field, easy to copy and understand | Not used by the team, not installed on the machine |

## Decision

**Rust** (axum + tower + sqlx). For the backend only — the UI is separate
(ADR-0005).

The case for Go rested on Go's proxy/HTTP ecosystem. ADR-0002 and ADR-0003
handed proxying to nginx and OIDC to oauth2-proxy — meaning we write none of the
layers Go is better at. What is left is a small HTTP + SQL service, and for that
the deciding factor becomes "the language you can actually maintain".

The team's existing projects (`k8rs`, `ratodo`, `dotpack`) are Rust; tokio and
rustls are already in use. Rust 1.97 is installed, Go is not.

## Consequences

- Reference implementations will be read in Go and written in Rust. An accepted cost.
- This decision binds **the backend only**. The UI is a separate component
  (ADR-0005) and its technology is chosen separately — the Rust decision does
  not constrain the frontend.
- Instead of `sqlx`'s macro API, which needs `DATABASE_URL` for compile-time SQL
  checking, the runtime API will be used; otherwise the project does not compile
  without a database.
- Build times are longer than Go's; CI should account for it.
