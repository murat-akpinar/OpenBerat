// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// What the backend asks Keycloak's Admin API for. Two things: the kill switch's
// first step (ADR-0019) — without it the other three are theatre, because
// deleting the oauth2-proxy session only sends the browser back to a Keycloak
// that still holds a live SSO session and signs the user straight back in with
// no password — and the directory reads and credential delete a second-factor
// reset walks (ADR-0036).
//
// It talks to the Admin API as a service account, not as the realm
// administrator: `manage-users` on one client is the narrowest role Keycloak
// offers for `logout-all`, and putting KC_ADMIN_PASSWORD in the backend's
// environment would hand password resets to whoever reads that environment.
// The same role covers everything below; ADR-0036 added no secret and no role,
// only calls.

use std::time::Duration;
use uuid::Uuid;

/// The two are different answers to the admin: one means the dependency is
/// down and the kill can be retried, the other means the sub names nobody and
/// retrying will not help. Reporting both as an outage sends an operator under
/// incident response to look at a Keycloak that is fine.
pub enum LogoutError {
    NoSuchUser,
    Unavailable(String),
}

impl std::fmt::Display for LogoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LogoutError::NoSuchUser => write!(f, "no such user in the realm"),
            LogoutError::Unavailable(why) => write!(f, "{why}"),
        }
    }
}

/// Both calls together are step 1 of four, and the whole kill switch has 5 s
/// (ADR-0016). Long enough for a busy Keycloak, short enough that a hung one
/// is reported rather than waited on.
const TIMEOUT: Duration = Duration::from_secs(2);

pub struct Keycloak {
    http: reqwest::Client,
    /// Base URL on the `core` network, no trailing slash.
    base: String,
    realm: String,
    client_id: String,
    client_secret: String,
}

impl Keycloak {
    pub fn new(
        http: &reqwest::Client,
        base: &str,
        realm: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Keycloak {
        Keycloak {
            http: http.clone(),
            base: base.trim_end_matches('/').to_string(),
            realm: realm.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
        }
    }

    /// Not cached. The kill switch runs during incident response, not on the
    /// request path, and a cached token is one more thing to be stale at the
    /// moment it matters.
    async fn token(&self) -> Result<String, String> {
        let response = self
            .http
            .post(format!(
                "{}/realms/{}/protocol/openid-connect/token",
                self.base, self.realm
            ))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ])
            .timeout(TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("Keycloak did not answer: {e}"))?;
        let status = response.status();
        // The body carries the access token on success and the client secret's
        // fate on failure; neither belongs in a log line, so only the status
        // is reported.
        let body = response
            .text()
            .await
            .map_err(|e| format!("Keycloak token response unreadable: {e}"))?;
        if !status.is_success() {
            return Err(format!("Keycloak refused the service account: {status}"));
        }
        serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["access_token"].as_str().map(str::to_owned))
            .ok_or_else(|| "Keycloak token response carried no access_token".to_string())
    }

    // --- Feature Start ---
    // `sub` is a Uuid and not a string because it is interpolated into an admin
    // API path. Keycloak's `sub` is the user id and is a UUID (docs/07,
    // VERIFY), so nothing legitimate is refused by insisting on one — while a
    // `sub` carrying `../` would otherwise reach a different admin endpoint
    // entirely, with the service account's rights.
    // --- Feature End ---
    pub async fn logout_all(&self, sub: &Uuid) -> Result<(), LogoutError> {
        let token = self.token().await.map_err(LogoutError::Unavailable)?;
        let response = self
            .http
            .post(format!(
                "{}/admin/realms/{}/users/{sub}/logout",
                self.base, self.realm
            ))
            .bearer_auth(token)
            .timeout(TIMEOUT)
            .send()
            .await
            .map_err(|e| LogoutError::Unavailable(format!("Keycloak did not answer: {e}")))?;
        match response.status() {
            status if status.is_success() => Ok(()),
            reqwest::StatusCode::NOT_FOUND => Err(LogoutError::NoSuchUser),
            status => Err(LogoutError::Unavailable(format!(
                "Keycloak refused logout-all: {status}"
            ))),
        }
    }

    /// Every Admin API read below answers an array and none of them is worth a
    /// representation struct: Keycloak's user is fifty fields deep and this
    /// takes four of them.
    async fn get(
        &self,
        token: &str,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, String> {
        let response = self
            .http
            .get(format!("{}/admin/realms/{}/{path}", self.base, self.realm))
            .bearer_auth(token)
            .query(query)
            .timeout(TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("Keycloak did not answer: {e}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "Keycloak refused the directory read: {}",
                response.status()
            ));
        }
        let body = response
            .text()
            .await
            .map_err(|e| format!("Keycloak answered the directory read unreadably: {e}"))?;
        serde_json::from_str(&body)
            .map_err(|e| format!("Keycloak answered the directory read unreadably: {e}"))
    }

    /// One page of the realm's users (ADR-0036). Read through on every call and
    /// stored nowhere: the subject of a reset is by definition someone who
    /// cannot log in, so the directory that already exists is the only honest
    /// place to list them from.
    pub async fn users(
        &self,
        search: &str,
        first: u32,
        max: u32,
        privileged_groups: [&str; 2],
    ) -> Result<Vec<User>, String> {
        let token = self.token().await?;
        let (first, max) = (first.to_string(), max.to_string());
        let mut query = vec![("first", first.as_str()), ("max", max.as_str())];
        if !search.is_empty() {
            query.push(("search", search));
        }
        let listed = self.get(&token, "users", &query).await?;
        // --- Feature Start ---
        // The privileged flag costs two calls a page rather than one a user:
        // reading every listed user's groups would put the directory's size on
        // the management path for a flag that only disables a button. It is a
        // convenience and not the control — `reset` re-reads the target's own
        // groups and never trusts this.
        let mut privileged = Vec::new();
        for group in privileged_groups {
            privileged.extend(self.members(&token, group).await?);
        }
        // --- Feature End ---
        Ok(listed
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|user| {
                let username = user["username"].as_str()?.to_string();
                Some(User {
                    privileged: privileged.contains(&username),
                    username,
                    email: user["email"].as_str().unwrap_or_default().to_string(),
                    totp: user["totp"].as_bool().unwrap_or(false),
                })
            })
            .collect())
    }

    /// The usernames in one group. Two calls, because Keycloak addresses a
    /// group by id and the name has to resolve first. A name nothing answers is
    /// an empty group rather than an error: an installation that has left
    /// AUDITOR_GROUP unset still gets its user list.
    async fn members(&self, token: &str, group: &str) -> Result<Vec<String>, String> {
        if group.is_empty() {
            return Ok(Vec::new());
        }
        let found = self
            .get(token, "groups", &[("search", group), ("exact", "true")])
            .await?;
        let id = found
            .as_array()
            .into_iter()
            .flatten()
            .find(|g| g["name"] == group)
            .and_then(|g| g["id"].as_str())
            .and_then(|id| Uuid::parse_str(id).ok());
        let Some(id) = id else {
            return Ok(Vec::new());
        };
        let members = self
            .get(token, &format!("groups/{id}/members"), &[])
            .await?;
        Ok(members
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| m["username"].as_str().map(str::to_owned))
            .collect())
    }

    /// What a reset has to know before it may run: the id the credential calls
    /// hang off, and the groups `policy::may_reset_second_factor` judges. `None`
    /// is a username the realm does not have, which is a 404 and not an outage.
    pub async fn target(&self, username: &str) -> Result<Option<Target>, String> {
        let token = self.token().await?;
        let found = self
            .get(
                &token,
                "users",
                &[("username", username), ("exact", "true")],
            )
            .await?;
        let Some(id) = found
            .as_array()
            .and_then(|users| users.first())
            .and_then(|user| user["id"].as_str())
        else {
            return Ok(None);
        };
        // The same insistence as `logout_all`: this is interpolated into an
        // Admin API path, with the service account's rights behind it.
        let id = Uuid::parse_str(id)
            .map_err(|_| "Keycloak named a user whose id is not a UUID".to_string())?;
        let groups = self.get(&token, &format!("users/{id}/groups"), &[]).await?;
        Ok(Some(Target {
            id,
            groups: groups
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|g| g["name"].as_str().map(str::to_owned))
                .collect(),
        }))
    }

    // --- Feature Start ---
    // The reset itself (ADR-0036), and it touches one credential type. The
    // federated password carries no id at all and only an id can be deleted, so
    // the narrowest thing that works is also all this can reach: filtering on
    // `otp` and deleting by id cannot take a password with it.
    // --- Feature End ---
    pub async fn delete_otp(&self, id: &Uuid) -> Result<usize, String> {
        let token = self.token().await?;
        let held = self
            .get(&token, &format!("users/{id}/credentials"), &[])
            .await?;
        let otp: Vec<Uuid> = held
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["type"] == "otp")
            .filter_map(|c| c["id"].as_str())
            .filter_map(|c| Uuid::parse_str(c).ok())
            .collect();
        for credential in &otp {
            let response = self
                .http
                .delete(format!(
                    "{}/admin/realms/{}/users/{id}/credentials/{credential}",
                    self.base, self.realm
                ))
                .bearer_auth(&token)
                .timeout(TIMEOUT)
                .send()
                .await
                .map_err(|e| format!("Keycloak did not answer: {e}"))?;
            // A delete that fails after an earlier one succeeded stops here and
            // is reported. The call is idempotent, so the answer to a partial
            // reset is to run it again.
            if !response.status().is_success() {
                return Err(format!(
                    "Keycloak refused the credential delete: {}",
                    response.status()
                ));
            }
        }
        Ok(otp.len())
    }
}

/// One row of `GET /api/admin/users`: a projection of Keycloak's own user, not
/// a stored directory. `totp` is Keycloak's own flag for "an OTP credential is
/// enrolled", which is why a row costs no call of its own (`docs/07`).
#[derive(serde::Serialize)]
pub struct User {
    pub username: String,
    pub email: String,
    pub totp: bool,
    pub privileged: bool,
}

/// The target of a reset, as far as the decision needs it.
pub struct Target {
    pub id: Uuid,
    pub groups: Vec<String>,
}
