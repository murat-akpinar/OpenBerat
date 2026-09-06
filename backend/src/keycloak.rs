// The kill switch's first step (ADR-0019). Without it the other three are
// theatre: deleting the oauth2-proxy session only sends the browser back to
// Keycloak, which still holds a live SSO session and signs the user straight
// back in with no password.
//
// It talks to the Admin API as a service account, not as the realm
// administrator: `manage-users` on one client is the narrowest role Keycloak
// offers for `logout-all`, and putting KC_ADMIN_PASSWORD in the backend's
// environment would hand password resets to whoever reads that environment.

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
}
