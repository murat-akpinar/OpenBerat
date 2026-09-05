// HTTP endpoints:
//   GET /decide       for the nginx auth_request — 200 / 401 / 403, never 5xx.
//                     Inputs: X-App-Slug, X-Original-URI, X-Original-Method,
//                     X-Real-IP, X-Request-Id, Cookie. Anything missing is a DENY.
//                     The Set-Cookie from oauth2-proxy is relayed verbatim;
//                     without it cookie_refresh silently stops (ADR-0006).
//   GET /api/apps     the applications the portal lists (called by the frontend)
//   /api/admin/*      application and entitlement management — requires ADMIN_GROUP
//                     membership, never cached, Origin checked on state-changing
//                     endpoints
// Contract: docs/02-architecture.md
