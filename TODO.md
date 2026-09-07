# TODO

Status: **phases 0–7 are closed and nothing is tagged.** The one box left
anywhere is HA, and N-06 puts it outside v1 — what closed each phase, and the
148 boxes that did it, moved to [`docs/09-history.md`](docs/09-history.md).
**The next thing is a tag**, not a box: cutting it is a deliberate manual act
([ADR-0023](docs/adr/0023-versioning-and-release.md)).

Decisions: `docs/adr/` · Open questions: `docs/06-requirements.md`

---

## Open

- [ ] Backend on 2 instances + nginx health check (HA — after the first deployment)
      *Not started: N-06 puts HA outside v1 and the box waits on a first real
      deployment. Two things are known before it opens, both from measurement.
      **nginx OSS has no `health_check` directive** — only passive
      `max_fails`/`fail_timeout`, which ejects an instance after users have
      already met the failure — so the check has to be NGINX Plus, a patched
      build, or something outside nginx that polls `/readyz` and rewrites the
      upstream list, the shape ADR-0011 already uses (`docs/07`). And the load
      test says **the first instance to add is nginx, not the backend**: at 32
      connections nginx used 138% of two cores and the backend 11%.
      The design question the cache raised is **answered**:
      [ADR-0031](docs/adr/0031-decision-cache-multi-instance.md) keeps the cache
      in memory and broadcasts its invalidations over the Redis ADR-0019 already
      requires, both transports measured (`docs/07`). What this box still owes
      it is the subscriber itself, the rule that an instance with no live
      subscription serves no cache hits, and a decision about the gap that rule
      leaves — a connection alive at TCP level with a wedged reader.*

---

## Later

- SSH/RDP → define Apache Guacamole as a protected application (ADR-0001)
- Per-person time-limited access (JIT access, `expires_at`) + the `known_user`
  table and person selection in admin
- Conditional access (IP, time, `acr`) → the `entitlement.conditions` column is
  added then
- A signed identity JWT to the upstream + a JWKS endpoint (`docs/06`, Security)
- A service-account / machine-to-machine access path (CI, monitoring, mobile)
- Audit hash chain (`prev_hash`) — stays here: ADR-0014 chose differentiators
  that are not audit-led, so it does not enter `0001_init.sql`
- SIEM integration, access reports
- One subject, two source addresses inside one window — a query over
  `audit_event.src_ip`, which already holds it; beside the access reports
- Group name ↔ SID drift auditing
- HA / multiple instances → the decision cache moves to Redis
