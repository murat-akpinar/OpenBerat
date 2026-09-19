// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// What the management plane refuses to store. Every value checked here is a
// trust boundary input: a `path_pattern` becomes a rule the PEP matches paths
// against, and a slug, a hostname or an `upstream_url` becomes a directive in
// generated nginx configuration (ADR-0011). The refusal is at the point of
// entry so the admin is told, and the same functions run again in `nginx.rs`
// on the way out, which is the last gate before the value *is* configuration.

use crate::policy;
use std::net::IpAddr;
use url::{Host, Url};

// --- Feature Start ---
// `matches` lower-cases the pattern and resolves `.`/`..`, but it does not
// percent-decode it and does not fold `\` — `policy::normalise` does both to
// the request path. A pattern that changes under normalisation is therefore one
// no request can ever equal, and the dangerous half is the deny rule: it never
// fires, the admin reads back what they typed and believes the path is closed.
// Refused rather than stored, for the reason the comma guard above gives.
// --- Feature End ---
// --- Feature Start ---
// ADR-0029, and the same judgement pointed the other way. `matches` strips the
// trailing `*` before comparing, so `/reports` and `/reports/*` are one rule —
// which makes `allow /reports` a grant over the whole subtree, read back by the
// admin as a single path. There is no exact-path form to mean instead, so the
// fix is to refuse the spelling that pretends to be one rather than to invent a
// meaning for it: narrowing it in `matches` would silently shrink every
// starless *deny* row already stored, which is the one direction a correction
// may never run.
// --- Feature End ---
pub fn validate_path_pattern(raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Ok(());
    }
    // `/*` satisfies this too: it is the whole application spelled the long way.
    if !raw.ends_with("/*") {
        let base = raw.trim_end_matches(['*', '/']);
        return Err(if base.is_empty() {
            "path_pattern for the whole application is empty, or /*".to_string()
        } else {
            format!(
                "path_pattern is a subtree and has no exact-path form: write {base}/*, \
                 which matches {base} and everything below it"
            )
        });
    }
    let probe = raw.strip_suffix('*').unwrap_or(raw);
    if probe.contains('*') {
        return Err("path_pattern may only use * as its last character".into());
    }
    match policy::normalise(probe) {
        Ok(seen) if seen == probe => Ok(()),
        Ok(seen) => Err(format!(
            "path_pattern must be written the way it is matched: {seen}"
        )),
        Err(_) => Err("path_pattern must be empty or start with /".into()),
    }
}

// --- Feature Start ---
// upstream_url is a trust boundary input (ADR-0011): it becomes a `proxy_pass`
// in generated nginx configuration, on an nginx that sits on *both* networks.
// A record naming an infrastructure service would publish Postgres or Redis
// through the proxy, and one naming a link-local address would publish a cloud
// metadata endpoint. Private ranges are deliberately allowed — every real
// upstream is on one.
// --- Feature End ---
pub fn validate_upstream(raw: &str) -> Result<(), String> {
    let url = Url::parse(raw).map_err(|_| "upstream_url is not a URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("upstream_url must be http or https".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("upstream_url must not carry credentials".into());
    }
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        return Err("upstream_url must be scheme://host:port with no path".into());
    }
    // Blunt, and deliberately so: an admin typing an IP address instead of a
    // service name would walk past the name check below, and nothing legitimate
    // behind this proxy speaks Postgres or Redis over HTTP.
    if let Some(port) = url.port()
        && [5432, 6379, 389, 636, 3268, 3269].contains(&port)
    {
        return Err("upstream_url names an infrastructure port".into());
    }
    match url.host().ok_or("upstream_url has no host".to_string())? {
        Host::Domain(name) => {
            let name = name.to_ascii_lowercase();
            if [
                "localhost",
                "postgres",
                "redis",
                "keycloak",
                "backend",
                "oauth2-proxy",
                "nginx",
                "samba-ad",
                "dc01",
            ]
            .contains(&name.as_str())
            {
                return Err("upstream_url names an infrastructure service".into());
            }
        }
        Host::Ipv4(ip) => reject_reserved(IpAddr::V4(ip))?,
        Host::Ipv6(ip) => reject_reserved(IpAddr::V6(ip))?,
    }
    Ok(())
}

fn reject_reserved(ip: IpAddr) -> Result<(), String> {
    let bad = match ip {
        // 169.254.0.0/16 is where a cloud metadata service lives.
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    };
    if bad {
        return Err("upstream_url names a loopback, link-local or multicast address".into());
    }
    Ok(())
}

// --- Feature Start ---
// The slug and the hostname are interpolated straight into a generated server
// block — `set $app_slug {slug};` and `server_name {hostname};` — so a value
// carrying a space, a newline or a semicolon is nginx configuration injection
// (ADR-0011). The shape is the schema's CHECK constraint, written here as well
// for two reasons: a value the API never validated came back from Postgres as a
// 503, so the guard read to the admin as an outage rather than as a refusal;
// and `render_apps_conf` — the last gate before the value *is* configuration —
// checked the upstream and the hostname's name but never the slug's shape.
// --- Feature End ---
/// Lower-case alphanumeric labels joined by single separators — the two CHECK
/// constraints of `0001_init.sql` written once, and without a regex crate to
/// state them in. An empty label is what refuses a leading, trailing or
/// doubled separator.
fn labelled(value: &str, separators: &[char]) -> bool {
    !value.is_empty()
        && value.split(|c| separators.contains(&c)).all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

pub fn validate_slug(slug: &str) -> Result<(), String> {
    if labelled(slug, &['-']) {
        return Ok(());
    }
    Err("slug must be lower-case letters and digits, separated by single hyphens".into())
}

/// A generated block for `portal.…` or `auth.…` would shadow the portal or the
/// login flow — and nginx would serve it without complaint, because the first
/// matching `server_name` wins (ADR-0011).
///
/// Answers with the lower-cased hostname, which is the one the caller must
/// store: this function already lower-cases before checking, so `WIKI.…` passed
/// it and then met a column whose CHECK is lower-case only — a 503 for a value
/// the handler had just accepted. It is also the spelling `explain` looks up
/// and the one nginx matches, neither of which cares how it was typed.
pub fn validate_hostname(hostname: &str, portal_origin: &str) -> Result<String, String> {
    let hostname = hostname.to_ascii_lowercase();
    if !labelled(&hostname, &['.', '-']) {
        return Err(
            "external_hostname must be lower-case letters and digits, separated by single dots or hyphens".into(),
        );
    }
    let first = hostname.split('.').next().unwrap_or_default();
    if ["portal", "auth"].contains(&first) {
        return Err("external_hostname uses a reserved name (portal, auth)".into());
    }
    if Url::parse(portal_origin)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|portal| portal == hostname)
    {
        return Err("external_hostname is the portal's own hostname".into());
    }
    Ok(hostname)
}

// --- Feature Start ---
// The two columns the portal draws and nothing else reads. Neither reaches
// generated configuration — `nginx.rs` interpolates the slug and the hostname
// and never these — so the bound is the layout's rather than a safety one:
// `portal.css` is built to survive a 200-character name, and nothing is built
// to survive an unbounded one. Both are returned trimmed, because the
// management screen trims and a row written through the API must not be a
// different row from the one the form would have written.
pub const LABEL_MAX: usize = 200;

pub fn validate_name(raw: &str) -> Result<&str, String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("name is required".into());
    }
    if name.chars().count() > LABEL_MAX {
        return Err(format!("name is at most {LABEL_MAX} characters"));
    }
    Ok(name)
}

/// `None` for an icon that is absent or blank: the portal falls back to the
/// first letter of the name, and a column holding two spaces is that fallback
/// written where nobody can see it.
pub fn validate_icon(raw: Option<&str>) -> Result<Option<&str>, String> {
    let icon = raw.map(str::trim).filter(|icon| !icon.is_empty());
    if icon.is_some_and(|icon| icon.chars().count() > LABEL_MAX) {
        return Err(format!("icon is at most {LABEL_MAX} characters"));
    }
    Ok(icon)
}
// --- Feature End ---

#[cfg(test)]
mod tests {
    use super::*;

    const PORTAL: &str = "https://portal.apps.example.local";

    // Both used to reach the database untouched. `""` broke a CHECK and came
    // back as an outage; `"   "` satisfied it and was stored, so the portal
    // drew a button with nothing on it.
    #[test]
    fn a_name_is_required_after_trimming_and_bounded() {
        assert_eq!(validate_name("  Wiki  ").unwrap(), "Wiki");
        for bad in ["", "   ", "\t\n"] {
            assert!(validate_name(bad).is_err(), "{bad:?} is not a name");
        }
        assert!(validate_name(&"W".repeat(LABEL_MAX)).is_ok());
        assert!(validate_name(&"W".repeat(LABEL_MAX + 1)).is_err());
        // Counted in characters and not bytes: a bound that measures UTF-8
        // would refuse a name a third as long once it is not written in ASCII.
        assert!(validate_name(&"ş".repeat(LABEL_MAX)).is_ok());
    }

    #[test]
    fn a_blank_icon_is_no_icon() {
        assert_eq!(validate_icon(Some("  W  ")).unwrap(), Some("W"));
        assert_eq!(validate_icon(Some("   ")).unwrap(), None);
        assert_eq!(validate_icon(None).unwrap(), None);
        // An emoji is several characters and a path is many; the same bound
        // holds both, and it is the one the layout was measured against.
        assert!(validate_icon(Some("/icons/jenkins.svg")).unwrap().is_some());
        assert!(validate_icon(Some(&"W".repeat(LABEL_MAX + 1))).is_err());
    }

    // A deny rule that can never fire is the one bug this file already refuses
    // for group names (the comma guard): the admin reads the rule back, sees
    // what they typed, and believes the path is closed.
    #[test]
    fn a_pattern_the_matcher_could_never_meet_is_refused() {
        // `policy::normalise` percent-decodes the request path and folds `\`
        // into `/`; the matcher does neither to the pattern. So each of these
        // is a rule no normalised path can equal.
        for bad in [
            "/%61dmin/*",  // decodes to /admin/ on the path side, stays literal here
            "/x\\admin/*", // a Windows upstream serves this as /x/admin/
            "/admin/%2e%2e/*",
            "/ADMIN/*", // the matcher lower-cases; stored as typed it reads as case-sensitive
            "/a//b/*",
            "/x/../admin/*",
        ] {
            assert!(
                validate_path_pattern(bad).is_err(),
                "{bad} should be refused"
            );
        }
    }

    // ADR-0029. `matches` strips the trailing `*` and prefix-matches either way,
    // so every one of these is the same rule as its `/*` form — and reads as a
    // narrower one. The dangerous half is the allow: `/reports` grants the whole
    // subtree while the admin reads back one path.
    #[test]
    fn a_pattern_that_is_not_a_subtree_is_refused() {
        for bad in ["/admin", "/reports", "/a/b", "/"] {
            assert!(
                validate_path_pattern(bad).is_err(),
                "{bad} is a subtree rule wearing an exact path's spelling"
            );
        }
        // Reads as a glob, behaves as a segment-bounded prefix: `/admin*` does
        // not match `/adminx`, whatever the star suggests.
        for bad in ["/admin*", "/a/b*"] {
            assert!(
                validate_path_pattern(bad).is_err(),
                "{bad} reads as a glob and is not one"
            );
        }
        // The sentence is the point of the whole change: the admin has to be
        // told what the rule they meant is spelled like, and that the spelling
        // they chose covers more than it looks like it does.
        assert_eq!(
            validate_path_pattern("/reports").unwrap_err(),
            "path_pattern is a subtree and has no exact-path form: \
             write /reports/*, which matches /reports and everything below it"
        );
    }

    #[test]
    fn an_ordinary_pattern_is_accepted() {
        for good in ["", "/*", "/admin/*", "/a/b/c/*"] {
            assert!(
                validate_path_pattern(good).is_ok(),
                "{good}: {:?}",
                validate_path_pattern(good)
            );
        }
    }

    #[test]
    fn an_upstream_may_be_an_ordinary_private_address() {
        for good in [
            "http://sample-app:80",
            "https://intranet.example.local",
            "http://10.1.2.3:8080",
            "http://172.19.0.5",
            "http://192.168.1.10:3000",
            "http://[fd00::1]:8080",
        ] {
            assert!(
                validate_upstream(good).is_ok(),
                "{good}: {:?}",
                validate_upstream(good)
            );
        }
    }

    #[test]
    fn an_upstream_may_not_be_the_infrastructure() {
        // Every one of these becomes a proxy_pass on an nginx that sits on both
        // networks, so each is a way to publish something that should never be
        // reachable from a browser.
        for bad in [
            "http://postgres:5432",
            "http://redis:6379",
            "http://keycloak:8080",
            "http://backend:8081",
            "http://oauth2-proxy:4180",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
            "http://169.254.169.254/", // cloud metadata
            "http://[fe80::1]:80",
            "http://0.0.0.0:80",
            "http://10.1.2.3:5432", // the name check would have missed this
            "http://10.1.2.3:389",  // and this is the directory
        ] {
            assert!(validate_upstream(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn an_upstream_is_a_host_and_a_port_and_nothing_else() {
        for bad in [
            "",
            "not a url",
            "ftp://files.example.local",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "http://user:pass@app.example.local",
            "http://app.example.local/some/path",
            "http://app.example.local/?a=1",
        ] {
            assert!(validate_upstream(bad).is_err(), "{bad} should be refused");
        }
    }

    // The last gate before a value becomes nginx configuration (ADR-0011). Each
    // of these renders a directive the admin did not write: `;` ends one and
    // starts another, a newline starts a line, and a space makes `set $app_slug`
    // take an argument nobody meant.
    #[test]
    fn a_slug_that_could_write_configuration_is_refused() {
        for bad in [
            "",
            "a;b",
            "wiki; return 200",
            "wiki\n    return 200;",
            "sample app",
            "Sample",
            "-lead",
            "trail-",
            "a--b",
            "a.b",
            "wiki}",
            "wiki$host",
        ] {
            assert!(validate_slug(bad).is_err(), "{bad:?} should be refused");
        }
        for good in ["wiki", "sample-app", "a", "app2", "a-b-c"] {
            assert!(
                validate_slug(good).is_ok(),
                "{good:?}: {:?}",
                validate_slug(good)
            );
        }
    }

    #[test]
    fn a_hostname_that_could_write_configuration_is_refused() {
        for bad in [
            "",
            "wiki.apps.example.local; return 200",
            "wiki apps",
            "wiki..apps",
            ".wiki",
            "wiki.",
            "wiki_apps",
            "wiki.apps.example.local}",
        ] {
            assert!(
                validate_hostname(bad, PORTAL).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn a_hostname_may_not_shadow_the_portal_or_the_login_flow() {
        assert!(validate_hostname("sample.apps.example.local", PORTAL).is_ok());
        for bad in [
            "portal.apps.example.local",
            "PORTAL.apps.example.local",
            "auth.apps.example.local",
            "portal.somewhere.else",
        ] {
            assert!(
                validate_hostname(bad, PORTAL).is_err(),
                "{bad} should be refused"
            );
        }
    }
}
