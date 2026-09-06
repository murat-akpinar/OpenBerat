# 0022 — Audit retention: the operator sets the period, the partition is the unit

- **Status:** Accepted
- **Date:** 2026-09-07

## Context

N-04 — the audit log retention period — has been open since `docs/06` was
written, marked *"depends on KVKK and internal policy"*. That is still true and
is not going to stop being true: how long access records may be kept is a fact
about the organisation running the product and its legal advice, not a design
choice we can make for it.

What could not stay open is the **mechanism**. `audit_event` has been
partitioned by month since `0001_init.sql`, with exactly one partition — the
default — and a note saying the monthly ones arrive with this work. Until they
do, the table only grows: an audit log with no expiry is both an unbounded disk
and, under KVKK, personal data kept for no stated period, which is the one thing
the legislation is unambiguous about.

So the decision here is not a number. It is: **who supplies the number, in what
unit, and what removes the data.**

## Options

| Option | Pro | Con |
|---|---|---|
| **A — a period fixed in code** | Nothing to configure, nothing to get wrong | Wrong for every operator whose policy differs, and the period being *theirs* is the part KVKK actually asks for. A security product that quietly decides how long its evidence lives is the wrong shape |
| **B — a period in days, rows removed with `DELETE`** | Exact to the day | A row-by-row pass over the largest table in the schema, leaving bloat behind a `VACUUM` nothing here runs. And it ignores the partitioning that is already in the schema for this purpose |
| **C — a period in months, a month dropped whole** | One DDL statement per expired month, no bloat, no long-running delete. Uses what `0001_init.sql` already built | The granularity is a month: "keep 12" means at least 12 and up to 13 |
| **D — `pg_partman` / `pg_cron`** | Maintained by people who do this full time | A Postgres extension baked into the image and a second scheduler beside the one the backend already runs (ADR-0004). Two moving parts bought for a `create table` and a `drop table` |

## Decision

**C, with the period supplied by the operator as `AUDIT_RETENTION_MONTHS`,
defaulting to 12.** The backend creates the current and next month's partitions
and drops every partition whose month is entirely older than the cutoff; the
default partition is never dropped and expired rows in it are deleted instead.
The unit is months because the unit that leaves is a month — a figure in days
would promise a precision the mechanism does not have.

A value that is not a whole number of months, 1 or more, is **fatal at
startup**. This is the only background task in the product that deletes, and a
typo in an environment variable must not be able to shorten how long the audit
log survives.

## Consequences

- **Retention is a floor, not a ceiling.** Keeping 12 months means the oldest
  surviving row can be a little over 13 months old. An operator whose policy is
  a *maximum* rather than a minimum sets one month less than the policy.
- The **default partition stays** and is never dropped. It is what keeps an
  `INSERT` for an uncovered month from failing off the request path, which is
  where audit writes happen. Rows that land in it are deleted at the same cutoff
  a partition would be dropped at, so nothing outlives retention by hiding there.
- If the backend is down across a whole month boundary, that month's rows land
  in the default partition and can no longer be split out of it — creating the
  partition fails, is logged, and does not stop the expiry half of the run. Those
  rows expire on the same cutoff as everyone else's, and the following month
  partitions itself normally.
- Audit records are otherwise immutable (`CONTRIBUTING.md`). **This is the single
  sanctioned exception**, and the deletion itself is recorded — not as a row in
  the table being emptied, but in the structured stdout stream a SIEM reads
  (F-23).
- Reversing costs nothing in code: the period is one variable. Keeping records
  far longer is a larger number, and the partitions already dropped are gone —
  a restore from backup is the only road back, which is why the default is
  deliberately not shorter than an annual audit cycle.
- N-04 is answered as *a mechanism with a default*, not as a number. The number
  stays the operator's, and `INSTALL.md` says so where they will be setting it.
