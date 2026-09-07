// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The nginx application blocks, rendered from the `application` table
// (ADR-0011): the one piece of the configuration that is not baked into the
// image, and therefore the one place a row can turn into a directive. Two
// files come out of the same rows — the normal one, which every block puts
// behind `protected.inc` and `decide.inc`, and the break-glass one, which puts
// nothing in front of them at all (ADR-0030).
//
// Nothing here decides anything or answers anything: it reads the table,
// validates every row again and writes two staged files. Installing them,
// running `nginx -t` and rolling back is the reloader's job in the nginx
// container, which is the only place an `nginx -t` can run.

use crate::admin::Application;
use crate::validate::{validate_hostname, validate_slug, validate_upstream};
use std::path::Path as FsPath;
use url::Url;

#[cfg(test)]
use uuid::Uuid;

/// The same work without a `Ctx`, because startup calls it too: the file is a
/// pure function of the table, so a database restored into an empty volume
/// brings every application back with nobody editing a row (INSTALL.md §9).
pub async fn publish_conf(
    pool: &sqlx::PgPool,
    dir: &str,
    portal_origin: &str,
) -> Result<(), String> {
    let applications: Vec<Application> = sqlx::query_as(
        "select id, slug, name, icon, upstream_url, external_hostname, enabled
           from application order by slug",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("reading applications: {e}"))?;

    stage(
        dir,
        "apps.conf",
        render_apps_conf(&applications, portal_origin),
    )
    .await?;
    // --- Feature Start ---
    // The same table, rendered a second time without the authorisation
    // (ADR-0030). Break-glass used to serve two hand-written lab hostnames, so
    // `docs/08` restored the lab and answered 404 to every real application —
    // at the one moment nobody has time to find that out. The name does not end
    // in `.conf` on purpose: `nginx.conf` globs `conf.d/generated/*.conf`, and a
    // break-glass block reaching the *normal* configuration is an application
    // served with no authorisation at all, on a running system, with `nginx -t`
    // reporting success.
    // --- Feature End ---
    stage(
        dir,
        "breakglass.apps",
        render_breakglass_conf(&applications, portal_origin),
    )
    .await
}

/// Written under a different name and renamed, so the reloader can never see
/// half a file: rename within a filesystem is atomic, a write is not.
async fn stage(dir: &str, name: &str, body: String) -> Result<(), String> {
    let writing = FsPath::new(dir).join(format!("{name}.writing"));
    let staged = FsPath::new(dir).join(format!("{name}.staged"));
    tokio::fs::write(&writing, body)
        .await
        .map_err(|e| format!("writing {}: {e}", writing.display()))?;
    tokio::fs::rename(&writing, &staged)
        .await
        .map_err(|e| format!("staging {}: {e}", staged.display()))
}

// --- Feature Start ---
// The generated blocks are a security boundary, not a convenience: every one of
// them has to pull in protected.inc (the X-Auth-* strip and the auth_request)
// and decide.inc. Forget either in this template and the claim falls for every
// application it generates, silently and with `nginx -t` reporting success
// (ADR-0011). A row that does not validate is skipped rather than rendered —
// one bad record must not take the whole file, and therefore every other
// application, down with it.
// --- Feature End ---
/// The certificate is not written here: it is set once at http level in
/// `nginx/conf.d/tls.inc`, so this template cannot drift from the hand-written
/// blocks over where the operator's certificate lives.
/// The rows that may become a `server` block, with the upstream already split
/// into host, port and scheme. **One list for both templates** (ADR-0030): a
/// row the normal file refuses to render must not be able to appear, with no
/// authorisation in front of it, in the break-glass one.
///
/// Belt and braces over the schema's CHECK constraints and the API's
/// validation: this is the last point before the value becomes nginx
/// configuration, and the only one that is not on a happy path.
fn renderable<'a>(
    applications: &'a [Application],
    portal_origin: &str,
) -> Vec<(&'a Application, String, u16, String)> {
    applications
        .iter()
        .filter(|app| app.enabled)
        .filter_map(|app| {
            if let Err(why) = validate_slug(&app.slug)
                .and_then(|()| validate_upstream(&app.upstream_url))
                .and_then(|()| validate_hostname(&app.external_hostname, portal_origin))
            {
                tracing::error!(slug = %app.slug, "skipping application in generated config: {why}");
                return None;
            }
            let url = Url::parse(&app.upstream_url).ok()?;
            let host = url.host_str()?.to_string();
            let port = url.port_or_known_default()?;
            Some((app, host, port, url.scheme().to_string()))
        })
        .collect()
}

pub fn render_apps_conf(applications: &[Application], portal_origin: &str) -> String {
    let mut out = String::from(
        "# Generated from the `application` table by the backend (ADR-0011).\n         # Do not edit: the next admin change overwrites it. The hand-written\n         # half of the configuration is in the image; only this file is not.\n",
    );
    for (app, host, port, scheme) in renderable(applications, portal_origin) {
        out.push_str(&format!(
            "\nserver {{\n\
             \x20   listen 443 ssl;\n\
             \x20   http2 on;\n\
             \x20   server_name {hostname};\n\n\
             \x20   # Fixed here, never taken from the request: the subrequest\n\
             \x20   # inherits the client's Host verbatim.\n\
             \x20   set $app_slug {slug};\n\n\
             \x20   include /etc/nginx/conf.d/errors.inc;\n\
             \x20   include /etc/nginx/conf.d/decide.inc;\n\n\
             \x20   location / {{\n\
             \x20       include /etc/nginx/conf.d/protected.inc;\n\
             \x20       set $upstream {host};\n\
             \x20       proxy_pass {scheme}://$upstream:{port};\n\
             \x20   }}\n\
             }}\n",
            hostname = app.external_hostname,
            slug = app.slug,
            host = host,
            port = port,
            scheme = scheme,
        ));
    }
    out
}

// --- Feature Start ---
// The same rows, with the authorisation taken out and nothing else (ADR-0030).
// What must survive is the strip in `breakglass/upstream.inc`: an upstream that
// learns the user from `X-Auth-*` (ADR-0021) cannot tell the PEP was bypassed,
// so a break-glass block that forgot it would turn "no authorisation" into
// "authorisation the client writes for itself" — worse than the outage it is
// there to fix. `errors.inc` and `decide.inc` are absent because there is
// nothing to sign in to and nothing to ask.
// --- Feature End ---
pub fn render_breakglass_conf(applications: &[Application], portal_origin: &str) -> String {
    let mut out = String::from(
        "# Generated from the `application` table by the backend (ADR-0030).\n         # BREAK-GLASS: these blocks serve the applications with NO authorisation.\n         # Read only by breakglass.conf, which nothing starts by itself.\n",
    );
    for (app, host, port, scheme) in renderable(applications, portal_origin) {
        out.push_str(&format!(
            "\nserver {{\n\
             \x20   listen 443 ssl;\n\
             \x20   http2 on;\n\
             \x20   server_name {hostname};\n\n\
             \x20   location / {{\n\
             \x20       include /etc/nginx/breakglass/upstream.inc;\n\
             \x20       set $upstream {host};\n\
             \x20       proxy_pass {scheme}://$upstream:{port};\n\
             \x20   }}\n\
             }}\n",
            hostname = app.external_hostname,
            host = host,
            port = port,
            scheme = scheme,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORTAL: &str = "https://portal.apps.example.local";

    fn app(slug: &str, upstream: &str, hostname: &str, enabled: bool) -> Application {
        Application {
            id: Uuid::nil(),
            slug: slug.into(),
            name: slug.into(),
            icon: None,
            upstream_url: upstream.into(),
            external_hostname: hostname.into(),
            enabled,
        }
    }

    #[test]
    fn every_generated_location_pulls_in_the_strip() {
        let rendered = render_apps_conf(
            &[
                app(
                    "wiki",
                    "http://wiki-app:8080",
                    "wiki.apps.example.local",
                    true,
                ),
                app("crm", "https://crm-app", "crm.apps.example.local", true),
            ],
            PORTAL,
        );
        // The one thing that must never be missing. Without it a generated
        // application trusts whatever X-Auth-* the client sent, and `nginx -t`
        // is perfectly happy (ADR-0011).
        assert_eq!(
            rendered
                .matches("include /etc/nginx/conf.d/protected.inc;")
                .count(),
            2
        );
        assert_eq!(
            rendered
                .matches("include /etc/nginx/conf.d/decide.inc;")
                .count(),
            2
        );
        assert_eq!(
            rendered
                .matches("include /etc/nginx/conf.d/errors.inc;")
                .count(),
            2
        );
        // One location per server, so the count above is per application and
        // not two includes on one of them and none on the other.
        assert_eq!(rendered.matches("location / {").count(), 2);
        assert_eq!(rendered.matches("server {").count(), 2);
        // The slug is fixed in the block, never read from the request.
        assert!(rendered.contains("set $app_slug wiki;"));
        // A variable in proxy_pass is what defers DNS to request time, so a
        // stopped upstream costs one 502 instead of nginx refusing to start.
        assert!(
            rendered.contains("set $upstream wiki-app;\n        proxy_pass http://$upstream:8080;")
        );
        // https keeps its scheme and its default port.
        assert!(rendered.contains("proxy_pass https://$upstream:443;"));
        // Never a `return`: that would run before auth_request and leave the
        // location open (nginx/conf.d/README.md rule 14).
        assert!(!rendered.contains("return "));
    }

    // --- ADR-0030 ---------------------------------------------------------
    // The property that matters runs in both directions, so it is asserted in
    // both: a generated *normal* block that lost `protected.inc` is an
    // application with no authorisation on a running system, and a generated
    // *break-glass* block that kept it is a break-glass that cannot serve
    // anything — it would ask a backend that is, by hypothesis, down.
    #[test]
    fn the_two_templates_never_swap_their_includes() {
        let rows = [app(
            "wiki",
            "http://wiki-app:8080",
            "wiki.apps.example.local",
            true,
        )];
        let normal = render_apps_conf(&rows, PORTAL);
        let breakglass = render_breakglass_conf(&rows, PORTAL);

        assert!(normal.contains("include /etc/nginx/conf.d/protected.inc;"));
        assert!(normal.contains("include /etc/nginx/conf.d/decide.inc;"));

        assert!(
            !breakglass.contains("protected.inc"),
            "break-glass must not carry the authorisation include"
        );
        assert!(
            !breakglass.contains("decide.inc"),
            "break-glass must not ask a backend that is down"
        );
        assert!(!breakglass.contains("auth_request"));
        // It still has to strip the X-Auth-* family: an upstream that trusts
        // those headers cannot tell the PEP was bypassed, so leaving them alone
        // turns "no authorisation" into "authorisation the client writes".
        assert!(breakglass.contains("include /etc/nginx/breakglass/upstream.inc;"));
        // Same hostname, same upstream, same slug-free block — nothing on the
        // client side changes while break-glass is active.
        assert!(breakglass.contains("server_name wiki.apps.example.local;"));
        assert!(
            breakglass
                .contains("set $upstream wiki-app;\n        proxy_pass http://$upstream:8080;")
        );
        assert!(!breakglass.contains("return "));
    }

    #[test]
    fn break_glass_skips_exactly_what_the_normal_file_skips() {
        // One list, one set of validators (ADR-0030). A row the normal file
        // refuses to render must not appear unauthenticated in the other.
        let rows = [
            app(
                "good",
                "http://good-app:80",
                "good.apps.example.local",
                true,
            ),
            app("pg", "http://postgres:5432", "pg.apps.example.local", true),
            app("shadow", "http://x:80", "portal.apps.example.local", true),
            app(
                "evil; return 200",
                "http://x:80",
                "evil.apps.example.local",
                true,
            ),
            app("off", "http://off-app:80", "off.apps.example.local", false),
        ];
        let breakglass = render_breakglass_conf(&rows, PORTAL);
        assert_eq!(breakglass.matches("server {").count(), 1);
        assert!(breakglass.contains("good.apps.example.local"));
        assert!(!breakglass.contains("postgres"));
        assert!(!breakglass.contains("portal.apps.example.local"));
        assert!(!breakglass.contains("return 200"));
        assert!(!breakglass.contains("off-app"));
    }

    #[test]
    fn a_row_that_should_not_be_there_is_skipped_not_rendered() {
        // The schema and the API both refuse these, so a row like this means
        // something reached the table another way. One bad record must not take
        // every other application down with it.
        let rendered = render_apps_conf(
            &[
                app(
                    "good",
                    "http://good-app:80",
                    "good.apps.example.local",
                    true,
                ),
                app("pg", "http://postgres:5432", "pg.apps.example.local", true),
                app("shadow", "http://x:80", "portal.apps.example.local", true),
                // The one the generator used to render as written: a slug is a
                // bare directive argument, so a `;` in it opens a second one.
                app(
                    "evil; return 200",
                    "http://x:80",
                    "evil.apps.example.local",
                    true,
                ),
                app("bad host", "http://x:80", "bad host.example", true),
                app("off", "http://off-app:80", "off.apps.example.local", false),
            ],
            PORTAL,
        );
        assert_eq!(rendered.matches("server {").count(), 1);
        assert!(rendered.contains("good.apps.example.local"));
        assert!(!rendered.contains("postgres"));
        assert!(!rendered.contains("portal.apps.example.local"));
        assert!(!rendered.contains("return 200"));
        assert!(!rendered.contains("bad host"));
        assert!(
            !rendered.contains("off-app"),
            "a disabled application has no block"
        );
    }
}
