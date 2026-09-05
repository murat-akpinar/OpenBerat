// HTTP endpoints:
//   GET /decide       for the nginx auth_request — 200 / 401 / 403, never 5xx.
//                     Inputs: X-App-Slug, X-Original-URI, X-Original-Method,
//                     X-Real-IP, X-Request-Id, Cookie. Anything missing is a DENY.
//                     The Set-Cookie from oauth2-proxy is relayed verbatim;
//                     without it cookie_refresh silently stops (ADR-0006).
//   GET /api/apps     the applications the portal lists (called by the frontend)
//   GET /healthz      the process is alive; no dependencies checked
//   GET /readyz       Postgres and Redis reachable — 200 or 503. /decide cannot
//                     report an outage (a dead DB looks like a denied user), so
//                     this is the only outage signal the operator has.
//   /api/admin/*      application and entitlement management — requires ADMIN_GROUP
//                     membership, never cached, Origin checked on state-changing
//                     endpoints
//   POST /api/admin/kill/{sub}
//                     four ordered steps: Keycloak logout-all -> the session keys
//                     from the sub -> session index -> that user's cache entries
//                     -> the index entry (ADR-0019). Reversing any pair lets a
//                     request in the gap refill what was just cleared.
// Contract: docs/02-architecture.md
