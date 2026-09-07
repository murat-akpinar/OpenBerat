// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// PDP — the authorisation decision. The heart of the project.
// Decision order and rules: docs/05-authz-model.md
// Stays a pure function (no DB access, inputs -> decision); its tests live here.
// URI normalisation belongs here too: matching on the raw path lets a request
// like /%61dmin/ skip a deny rule (docs/05 "Path normalisation").

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

/// One entitlement row, already narrowed to this user's groups and this
/// application by the store query (docs/05, "Decision cache").
#[derive(Debug, Clone)]
pub struct Rule {
    pub effect: Effect,
    pub path_pattern: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Why access was refused. Logged, never shown to the user (docs/02). One
/// vocabulary for the audit column and the code; the last three are the
/// caller's, not `decide`'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Deny {
    MalformedUri,
    ApplicationDisabled,
    ExplicitDeny,
    NoMatchingGrant,
    MissingContext,
    StoreUnavailable,
    AuthUnavailable,
}

impl Deny {
    /// Every reason, for the /metrics counter that needs one series each. The
    /// exhaustive match below is what stops a new variant being added without
    /// this list being seen; the counter indexes by discriminant and falls back
    /// to no series rather than out of bounds, so forgetting it loses a number
    /// and never a request (`metrics.rs`).
    pub const ALL: [Deny; 7] = [
        Deny::MalformedUri,
        Deny::ApplicationDisabled,
        Deny::ExplicitDeny,
        Deny::NoMatchingGrant,
        Deny::MissingContext,
        Deny::StoreUnavailable,
        Deny::AuthUnavailable,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Deny::MalformedUri => "malformed_uri",
            Deny::ApplicationDisabled => "application_disabled",
            Deny::ExplicitDeny => "explicit_deny",
            Deny::NoMatchingGrant => "no_matching_grant",
            Deny::MissingContext => "missing_context",
            Deny::StoreUnavailable => "store_unavailable",
            Deny::AuthUnavailable => "auth_unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    Allow,
    Deny(Deny),
}

impl Decision {
    /// The `(decision, reason)` pair the audit columns hold. One vocabulary for
    /// the two places an outcome is named: an explain screen calling a refusal
    /// something the audit record does not is an admin comparing two answers
    /// that only look different.
    pub fn as_pair(self) -> (&'static str, &'static str) {
        match self {
            Decision::Allow => ("allow", "allowed"),
            Decision::Deny(reason) => ("deny", reason.as_str()),
        }
    }
}

// --- Feature Start ---
// Every deny rule in the product depends on this function. `X-Original-URI`
// arrives as the client wrote it, and prefix-matching that string lets
// `/%61dmin/`, `//admin/`, `/x/../admin/` and `/ADMIN/` all walk past a
// `/admin/*` rule while the upstream serves them the same page (docs/05).
// --- Feature End ---
pub fn normalise(raw_uri: &str) -> Result<String, Deny> {
    let path = raw_uri.split('?').next().unwrap_or_default();
    if !path.starts_with('/') {
        return Err(Deny::MalformedUri);
    }
    let decoded = String::from_utf8(percent_decode(path)?).map_err(|_| Deny::MalformedUri)?;
    // One decode round only. A `%` still in the output is a second layer the
    // upstream may well peel, which is how `/%2561dmin/` becomes `/admin/`.
    if decoded.contains('%') {
        return Err(Deny::MalformedUri);
    }
    // `%00` truncates the path inside some upstream frameworks, and the rest
    // of the control range is log and header injection (docs/05).
    if decoded.chars().any(char::is_control) {
        return Err(Deny::MalformedUri);
    }
    // Windows upstreams accept `\` as a separator, so a resolver that only
    // knows `/` leaves `/x\..\admin/` unresolved and the deny rule unmatched.
    let mut out = resolve(&decoded.replace('\\', "/"));
    // ASCII only: Unicode case folding maps distinct characters onto the same
    // one, which would decide two different paths are the same path.
    out.make_ascii_lowercase();
    Ok(out)
}

/// One round, and anything that is not a complete `%XX` escape is refused
/// rather than passed through — the pass-through is what turns a decoder into
/// a bypass.
fn percent_decode(path: &str) -> Result<Vec<u8>, Deny> {
    let raw = path.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] != b'%' {
            out.push(raw[i]);
            i += 1;
            continue;
        }
        let esc = raw.get(i + 1..i + 3).ok_or(Deny::MalformedUri)?;
        let hi = (esc[0] as char).to_digit(16).ok_or(Deny::MalformedUri)?;
        let lo = (esc[1] as char).to_digit(16).ok_or(Deny::MalformedUri)?;
        out.push((hi * 16 + lo) as u8);
        i += 3;
    }
    Ok(out)
}

/// Collapses repeated separators and resolves `.` / `..`, clamped at the root
/// so `/../admin/` cannot climb out of it.
fn resolve(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let mut out = String::from("/");
    out.push_str(&segments.join("/"));
    // A trailing slash is kept: it is the difference between the collection and
    // the resource for some upstreams, and the matcher accepts either.
    if !segments.is_empty()
        && (path.ends_with('/') || path.ends_with("/.") || path.ends_with("/.."))
    {
        out.push('/');
    }
    out
}

pub fn decide(app_enabled: bool, rules: &[Rule], raw_uri: &str, now: DateTime<Utc>) -> Decision {
    let path = match normalise(raw_uri) {
        Ok(p) => p,
        Err(reason) => return Decision::Deny(reason),
    };
    if !app_enabled {
        return Decision::Deny(Deny::ApplicationDisabled);
    }
    let live = |r: &&Rule| r.expires_at.is_none_or(|e| e > now);
    if rules
        .iter()
        .filter(live)
        .any(|r| r.effect == Effect::Deny && matches(&r.path_pattern, &path))
    {
        return Decision::Deny(Deny::ExplicitDeny);
    }
    if rules
        .iter()
        .filter(live)
        .any(|r| r.effect == Effect::Allow && matches(&r.path_pattern, &path))
    {
        return Decision::Allow;
    }
    Decision::Deny(Deny::NoMatchingGrant)
}

/// `/admin/*` matches `/admin`, `/admin/` and everything below it, and does not
/// match `/adminx` — the boundary is a segment, not a character (docs/05 rule 3).
/// An empty pattern is the whole application.
// ponytail: the pattern is normalised on every request rather than once when
// the rules are cached. A handful of rules per user makes it noise; move it to
// the cache fill if N-01 ever needs the microseconds.
fn matches(pattern: &str, path: &str) -> bool {
    let mut base = resolve(pattern.trim_end_matches('*'));
    base.make_ascii_lowercase();
    let base = base.trim_end_matches('/');
    base.is_empty()
        || path == base
        || path
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Why `decide` answered as it did, for the admin's explain screen
/// (`/api/admin/explain`). The verdict is **`decide`'s own** — this annotates
/// the rules it walked rather than deciding again, so the screen and the PEP
/// cannot drift into disagreeing about the same request.
#[derive(Debug)]
pub struct Trace {
    pub decision: Decision,
    /// `None` when the URI never became a path: the deny is `malformed_uri`
    /// and no rule was consulted.
    pub path: Option<String>,
    /// One entry per rule given, in that order.
    pub rules: Vec<RuleTrace>,
}

/// An expired rule that matches is reported as `matched` **and** `expired`
/// rather than dropped — "the grant ran out on Tuesday" is the answer the
/// admin came for, and an absent row would read as "there was never a grant".
#[derive(Debug, PartialEq, Eq)]
pub struct RuleTrace {
    pub matched: bool,
    pub expired: bool,
}

pub fn explain(app_enabled: bool, rules: &[Rule], raw_uri: &str, now: DateTime<Utc>) -> Trace {
    let path = normalise(raw_uri).ok();
    Trace {
        decision: decide(app_enabled, rules, raw_uri, now),
        rules: rules
            .iter()
            .map(|r| RuleTrace {
                // A path we refused to normalise was matched against nothing.
                matched: path.as_deref().is_some_and(|p| matches(&r.path_pattern, p)),
                expired: r.expires_at.is_some_and(|e| e <= now),
            })
            .collect(),
        path,
    }
}

pub fn is_admin(groups: &[String], admin_group: &str) -> bool {
    groups.iter().any(|g| g == admin_group)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `metrics.rs` indexes its per-reason counters by discriminant and reads
    /// the names back out of `ALL`. Out of order, and every denial is filed
    /// under somebody else's name.
    #[test]
    fn every_deny_reason_sits_at_its_own_discriminant() {
        for (index, reason) in Deny::ALL.iter().enumerate() {
            assert_eq!(*reason as usize, index, "{}", reason.as_str());
        }
    }

    fn rule(effect: Effect, path_pattern: &str) -> Rule {
        Rule {
            effect,
            path_pattern: path_pattern.to_string(),
            expires_at: None,
        }
    }

    fn now() -> DateTime<Utc> {
        "2026-09-06T12:00:00Z".parse().unwrap()
    }

    /// The application is open to the group, except /admin/* — the shape every
    /// path test below attacks.
    fn admin_denied() -> Vec<Rule> {
        vec![rule(Effect::Allow, ""), rule(Effect::Deny, "/admin/*")]
    }

    fn decision(uri: &str) -> Decision {
        decide(true, &admin_denied(), uri, now())
    }

    // Every row of the docs/05 "Path normalisation" table.
    #[test]
    fn deny_rule_survives_a_rewritten_path() {
        for uri in [
            "/admin/users",
            "/%61dmin/users",
            "//admin/users",
            "/x/../admin/users",
            "/admin",
            "/admin/",
            "/./admin/users",
            "/ADMIN/users",
            "/admin/users?next=/public",
            "/x/..//./admin/",
            "/admin%2fusers", // an encoded separator the upstream may decode
            "/%2e%2e/admin/", // encoded dot-dot
            "/public/../admin/",
        ] {
            assert_eq!(
                decision(uri),
                Decision::Deny(Deny::ExplicitDeny),
                "{uri} must reach the /admin/* deny rule"
            );
        }
    }

    // A separator the upstream may honour and we may not: on IIS `/x\..\admin/`
    // is `/admin/`, and a `..` resolver that only knows `/` walks straight past
    // the deny rule.
    #[test]
    fn backslash_is_a_separator() {
        for uri in ["/admin\\users", "/%5cadmin/", "/x\\..\\admin/"] {
            assert_eq!(
                decision(uri),
                Decision::Deny(Deny::ExplicitDeny),
                "{uri} must reach the /admin/* deny rule"
            );
        }
    }

    #[test]
    fn matching_stops_at_a_segment_boundary() {
        for uri in ["/adminx", "/administration/", "/public/admin-notes"] {
            assert_eq!(decision(uri), Decision::Allow, "{uri} is not under /admin/");
        }
    }

    #[test]
    fn double_encoding_is_refused() {
        for uri in ["/%2561dmin/", "/%25", "/a%252e%252e/admin/"] {
            assert_eq!(
                decision(uri),
                Decision::Deny(Deny::MalformedUri),
                "{uri} survives one decode round with a % still in it"
            );
        }
    }

    #[test]
    fn control_bytes_and_invalid_utf8_are_refused() {
        for uri in [
            "/admin%00.png", // NUL truncates the path inside some upstreams
            "/admin%0a/x",   // header/log injection downstream
            "/admin%09",
            "/%ff%fe",      // not UTF-8 after decoding
            "/%c0%af",      // overlong encoding of '/'
            "/admin%c2%80", // C1 control: valid UTF-8, still a control
        ] {
            assert_eq!(
                decision(uri),
                Decision::Deny(Deny::MalformedUri),
                "{uri} must not reach the matcher"
            );
        }
    }

    #[test]
    fn malformed_percent_escapes_are_refused() {
        for uri in ["/%zz", "/%a", "/%", "/admin/%g0"] {
            assert_eq!(
                decision(uri),
                Decision::Deny(Deny::MalformedUri),
                "{uri} is not a percent escape"
            );
        }
    }

    #[test]
    fn a_uri_that_is_not_a_path_is_refused() {
        for uri in ["", "*", "http://elsewhere/admin/", "admin/"] {
            assert_eq!(
                decision(uri),
                Decision::Deny(Deny::MalformedUri),
                "{uri} is not an origin-form path"
            );
        }
    }

    #[test]
    fn the_query_string_is_not_part_of_the_path() {
        // Matching the raw string would let the query carry the deny rule's
        // prefix, and let it hide the real one.
        assert_eq!(decision("/public?next=/admin/"), Decision::Allow);
        assert_eq!(
            decision("/admin/?next=/public"),
            Decision::Deny(Deny::ExplicitDeny)
        );
    }

    #[test]
    fn no_matching_rule_is_a_deny() {
        assert_eq!(
            decide(true, &[], "/", now()),
            Decision::Deny(Deny::NoMatchingGrant)
        );
        assert_eq!(
            decide(
                true,
                &[rule(Effect::Allow, "/reports/*")],
                "/payroll/",
                now()
            ),
            Decision::Deny(Deny::NoMatchingGrant)
        );
    }

    #[test]
    fn deny_beats_allow_whatever_the_order() {
        let forward = vec![rule(Effect::Allow, ""), rule(Effect::Deny, "/admin/*")];
        let reverse = vec![rule(Effect::Deny, "/admin/*"), rule(Effect::Allow, "")];
        for rules in [forward, reverse] {
            assert_eq!(
                decide(true, &rules, "/admin/", now()),
                Decision::Deny(Deny::ExplicitDeny)
            );
        }
        // Even when the allow is the more specific of the two.
        let rules = vec![
            rule(Effect::Allow, "/admin/reports/*"),
            rule(Effect::Deny, "/admin/*"),
        ];
        assert_eq!(
            decide(true, &rules, "/admin/reports/q1", now()),
            Decision::Deny(Deny::ExplicitDeny)
        );
    }

    #[test]
    fn an_expired_entitlement_is_ignored() {
        let expired = |effect, pattern| Rule {
            expires_at: Some("2026-09-06T11:59:59Z".parse().unwrap()),
            ..rule(effect, pattern)
        };
        assert_eq!(
            decide(true, &[expired(Effect::Allow, "")], "/", now()),
            Decision::Deny(Deny::NoMatchingGrant)
        );
        // Both directions: an expired deny stops denying (docs/05 rule 5).
        let rules = vec![rule(Effect::Allow, ""), expired(Effect::Deny, "/admin/*")];
        assert_eq!(decide(true, &rules, "/admin/", now()), Decision::Allow);
        // One second the other way and it still applies.
        let live = Rule {
            expires_at: Some("2026-09-06T12:00:01Z".parse().unwrap()),
            ..rule(Effect::Allow, "")
        };
        assert_eq!(decide(true, &[live], "/", now()), Decision::Allow);
    }

    #[test]
    fn a_disabled_application_denies_everyone() {
        assert_eq!(
            decide(false, &[rule(Effect::Allow, "")], "/", now()),
            Decision::Deny(Deny::ApplicationDisabled)
        );
    }

    #[test]
    fn an_empty_pattern_is_the_whole_application() {
        for uri in ["/", "/anything/at/all", "/admin-ish"] {
            assert_eq!(
                decide(true, &[rule(Effect::Allow, "")], uri, now()),
                Decision::Allow
            );
        }
    }

    #[test]
    fn admin_group_membership_is_an_exact_match() {
        let groups = |names: &[&str]| names.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(is_admin(&groups(&["OpenBerat-Admins"]), "OpenBerat-Admins"));
        assert!(is_admin(
            &groups(&["OpenBerat-Finance", "OpenBerat-Admins"]),
            "OpenBerat-Admins"
        ));
        // A portal user is not an admin, and neither is anything that merely
        // looks like the group: ADR-0008 matches by name, and failing on a
        // renamed group is the direction it chose to fail in.
        for not_admin in [
            vec![],
            groups(&["OpenBerat-Finance"]),
            groups(&["openberat-admins"]),
            groups(&["OpenBerat-Admins-Readonly"]),
            groups(&["Domain Admins"]),
        ] {
            assert!(!is_admin(&not_admin, "OpenBerat-Admins"));
        }
    }

    #[test]
    fn explain_never_disagrees_with_decide() {
        // The one property that matters: a screen that answers differently from
        // the PEP is worse than no screen. Every rule set and URI the tests
        // above attack, run through both.
        let expired = |effect, pattern| Rule {
            expires_at: Some("2026-09-06T11:59:59Z".parse().unwrap()),
            ..rule(effect, pattern)
        };
        let corpus = [
            admin_denied(),
            vec![],
            vec![rule(Effect::Allow, "")],
            vec![rule(Effect::Allow, "/reports/*")],
            vec![expired(Effect::Allow, "")],
            vec![rule(Effect::Allow, ""), expired(Effect::Deny, "/admin/*")],
        ];
        for rules in &corpus {
            for enabled in [true, false] {
                for uri in [
                    "/",
                    "/admin/",
                    "/%61dmin/",
                    "/x/../admin/",
                    "/adminx",
                    "/%2561dmin/",
                    "/admin%00",
                    "/%zz",
                    "",
                    "/reports/q1",
                    "/admin/users?next=/public",
                ] {
                    assert_eq!(
                        explain(enabled, rules, uri, now()).decision,
                        decide(enabled, rules, uri, now()),
                        "{uri} with {rules:?} enabled={enabled}"
                    );
                }
            }
        }
    }

    #[test]
    fn explain_names_the_rules_that_matched() {
        let rules = admin_denied(); // allow "", deny "/admin/*"
        let denied = explain(true, &rules, "/x/../admin/users", now());
        assert_eq!(denied.decision, Decision::Deny(Deny::ExplicitDeny));
        // The normalised path is the answer to half the tickets this endpoint
        // exists for: the admin wrote /admin/* and the user typed something else.
        assert_eq!(denied.path.as_deref(), Some("/admin/users"));
        assert_eq!(
            denied.rules,
            vec![
                RuleTrace {
                    matched: true,
                    expired: false
                },
                RuleTrace {
                    matched: true,
                    expired: false
                },
            ]
        );
        let allowed = explain(true, &rules, "/public/", now());
        assert_eq!(allowed.decision, Decision::Allow);
        assert_eq!(
            allowed.rules,
            vec![
                RuleTrace {
                    matched: true,
                    expired: false
                },
                RuleTrace {
                    matched: false,
                    expired: false
                },
            ]
        );
    }

    #[test]
    fn an_expired_grant_is_reported_as_expired_not_as_absent() {
        let ran_out = Rule {
            expires_at: Some("2026-09-06T11:59:59Z".parse().unwrap()),
            ..rule(Effect::Allow, "")
        };
        let trace = explain(true, &[ran_out], "/", now());
        assert_eq!(trace.decision, Decision::Deny(Deny::NoMatchingGrant));
        assert_eq!(
            trace.rules,
            vec![RuleTrace {
                matched: true,
                expired: true
            }],
            "dropping the row would read as `there was never a grant`"
        );
    }

    #[test]
    fn a_malformed_uri_is_matched_against_nothing() {
        let trace = explain(true, &admin_denied(), "/%2561dmin/", now());
        assert_eq!(trace.decision, Decision::Deny(Deny::MalformedUri));
        assert_eq!(trace.path, None);
        assert!(trace.rules.iter().all(|r| !r.matched));
    }

    #[test]
    fn a_disabled_application_still_shows_its_rules() {
        // The admin's question is usually "why not", and "the application is
        // switched off" must not hide the grants that would otherwise apply.
        let trace = explain(false, &admin_denied(), "/", now());
        assert_eq!(trace.decision, Decision::Deny(Deny::ApplicationDisabled));
        assert_eq!(trace.path.as_deref(), Some("/"));
        assert!(trace.rules[0].matched);
    }
}
