// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// What the portal page calls: who am I, what may I open, and sign me out.
// None of it decides anything the PEP does not — `apps` runs `policy::decide`
// over the same rules `/decide` would, and `me`'s `admin` flag only hides a
// button (ADR-0007). Every handler here is behind `api::indexed`, so the
// session is in the kill-switch index before any of them answers.

use crate::api::{AUTH_TIMEOUT, Caller, Ctx, from_portal};
use crate::cache;
use crate::policy::{self, Decision};
use crate::session;
use crate::store;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use std::sync::Arc;

// --- Feature Start ---
// The caller's own kill switch (docs/02, "Logout"), and the four steps are the
// kill switch's four in the same order for the same reasons. The IdP first, or
// the browser is signed straight back in with no password; the oauth2-proxy
// session before the cache, or a request in the gap refills the cache from a
// session that is still there; the index entry last, because it is the map to
// everything above it.
//
// Why the sign-out is a call from here rather than a redirect the browser
// walks afterwards: oauth2-proxy performs the RP-initiated logout out of the
// session's own id_token, which is inside the session it is being asked to
// destroy. Deleting the session key first leaves it nothing to log out with —
// measured on the lab, where exactly that left the IdP session alive and the
// next request signed the user back in without a prompt (docs/07). Ordering it
// here is what makes the four steps one call instead of a race with the
// browser's next navigation.
//
// Only this browser leaves the index. `forget` would take the same user's other
// sessions with it, and a live session in no index is one the kill switch
// cannot find.
// --- Feature End ---
pub(crate) async fn logout(State(ctx): State<Arc<Ctx>>, headers: HeaderMap) -> Response {
    let Some(caller) = Caller::from(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !from_portal(&headers, &ctx.portal_origin) {
        tracing::warn!(actor = %caller.username, "logout refused: wrong or missing Origin");
        return StatusCode::FORBIDDEN.into_response();
    }
    // Unreachable through nginx: `indexed` runs first and answers 503 for an
    // authenticated request whose session key cannot be derived.
    let Some(cookie) = headers.get("cookie") else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(key) = cache::session_cookie(cookie.to_str().ok())
        .and_then(|v| session::session_key(v, cache::COOKIE_NAME))
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // A failed step stops the ones after it: carrying on would report a logout
    // nobody got. The sign-out link's own href is the retry — it is steps 1 and
    // 2 on its own.
    let refused = |step: &str| {
        tracing::error!(actor = %caller.username, step, "logout failed");
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    };
    let signed_out = ctx
        .http
        .get(format!("{}/oauth2/sign_out", ctx.oauth2_proxy))
        .header("cookie", cookie)
        .timeout(AUTH_TIMEOUT)
        .send()
        .await;
    // The 302 is the answer, not something to follow (main.rs).
    match signed_out {
        Ok(response) if response.status().is_success() || response.status().is_redirection() => {}
        Ok(response) => {
            tracing::error!(status = %response.status(), "oauth2-proxy refused the sign-out");
            return refused("oauth2_proxy_sign_out");
        }
        Err(e) => {
            tracing::error!(error = %e, "oauth2-proxy did not answer the sign-out");
            return refused("oauth2_proxy_sign_out");
        }
    }
    // oauth2-proxy has just dropped this session itself. The DEL is still ours:
    // it is the step that actually cuts access, and a sign-out that answered
    // without deleting would otherwise leave the session live and unnoticed.
    if let Err(e) = ctx.index.drop_sessions(std::slice::from_ref(&key)).await {
        tracing::error!(error = %e, "deleting the oauth2-proxy session failed");
        return refused("delete_session");
    }
    ctx.cache.drop_sub(&caller.sub);
    if let Err(e) = ctx.index.forget_session(&caller.sub, &key).await {
        tracing::error!(error = %e, "dropping the index entry failed");
        return refused("forget_index_entry");
    }
    tracing::info!(actor = %caller.username, "logout");
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Serialize)]
struct PortalApp {
    slug: String,
    name: String,
    icon: Option<String>,
    url: String,
}

// --- Feature Start ---
// The portal grants nothing: this list is `policy::decide` run over the same
// rules the PEP would use, at the application's root. A second implementation
// of "can this user reach it" would eventually disagree with the first, and the
// disagreement shows up either as a button that 403s or — worse — as an
// application the portal hides while the PEP allows it.
// --- Feature End ---
pub(crate) async fn apps(State(ctx): State<Arc<Ctx>>, headers: HeaderMap) -> Response {
    let Some(caller) = Caller::from(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let found = match store::portal_apps(&ctx.pool, &caller.sub, &caller.groups).await {
        Ok(found) => found,
        Err(e) => {
            tracing::error!(error = %e, "listing portal applications failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let now = chrono::Utc::now();
    let reachable: Vec<PortalApp> = found
        .into_iter()
        .filter(|app| policy::decide(true, &app.rules, "/", now) == Decision::Allow)
        .map(|app| PortalApp {
            slug: app.slug,
            name: app.name,
            icon: app.icon,
            url: format!("https://{}/", app.external_hostname),
        })
        .collect();
    Json(reachable).into_response()
}

#[derive(Serialize)]
struct Me {
    sub: String,
    username: String,
    email: String,
    groups: Vec<String>,
    admin: bool,
}

pub(crate) async fn me(State(ctx): State<Arc<Ctx>>, headers: HeaderMap) -> Response {
    let Some(caller) = Caller::from(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // The frontend uses this to hide things. Hiding is a convenience; the
    // refusal is the guard in admin.rs (ADR-0007).
    let admin = policy::is_admin(&caller.groups, &ctx.admin_group);
    Json(Me {
        sub: caller.sub,
        username: caller.username,
        email: caller.email,
        groups: caller.groups,
        admin,
    })
    .into_response()
}
