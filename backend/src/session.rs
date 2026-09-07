// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The sub -> oauth2-proxy session key index (ADR-0019).
//
// oauth2-proxy's Redis store is keyed by a ticket derived from the session
// cookie, not by the user, and it exposes no "terminate this user's sessions"
// API. Without this index the kill switch degrades to Keycloak logout-all plus
// waiting for cookie_refresh — five minutes rather than the five seconds
// ADR-0016 promises.
//
// The one moment the session key is derivable is a decision-cache miss, because
// that is when the backend holds the raw cookie. It stores keys, not tokens: a
// revocation aid, not a second session store.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use std::collections::HashMap;
use std::time::Duration;

/// Must be at least oauth2-proxy's `cookie_expire` — `10h` in
/// `oauth2-proxy.cfg` since it was cut to the realm's own `ssoSessionMaxLifespan`
/// (`docs/04`). This stays far above it deliberately, because the two failures
/// are not symmetric: too long only means the kill switch deletes a key that
/// has already gone, too short means it cannot find a live session, and an
/// operator who raises `cookie_expire` does not read this file.
const INDEX_TTL: Duration = Duration::from_secs(8 * 24 * 60 * 60);

const INDEX_PREFIX: &str = "openberat:sessions:";

fn index_key(sub: &str) -> String {
    format!("{INDEX_PREFIX}{sub}")
}

// --- Feature Start ---
// The derivation is measured, not guessed (docs/07, VERIFY (4)). The cookie is
//     base64( "v2." + base64url(handle) + "." + base64url(secret) ) |ts|hmac
// and the handle decodes to the Redis key itself. No oauth2-proxy secret is
// involved: the secret half only decrypts the session payload, which the kill
// switch never reads. The prefix check at the end is the guard that matters —
// a value that does not decode to one of our own keys is not something the kill
// switch may later hand to DEL.
// --- Feature End ---
pub fn session_key(cookie_value: &str, cookie_name: &str) -> Option<String> {
    let signed = cookie_value.split('|').next()?;
    let ticket = String::from_utf8(decode(signed)?).ok()?;
    let handle = ticket.strip_prefix("v2.")?.split('.').next()?;
    let key = String::from_utf8(decode(handle)?).ok()?;
    key.starts_with(&format!("{cookie_name}-")).then_some(key)
}

/// oauth2-proxy writes URL-safe base64 without padding; the other alphabets are
/// tried so that a version which pads, or uses the standard alphabet, does not
/// silently produce an unkillable session.
fn decode(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .or_else(|_| STANDARD.decode(value))
        .ok()
}

#[derive(Clone)]
pub struct Index(ConnectionManager);

impl Index {
    pub async fn connect(url: &str) -> Result<Index, redis::RedisError> {
        let client = redis::Client::open(url)?;
        Ok(Index(ConnectionManager::new(client).await?))
    }

    /// Called on a cache miss, before the ALLOW that depends on it.
    pub async fn record(&self, sub: &str, session_key: &str) -> Result<(), redis::RedisError> {
        let mut redis = self.0.clone();
        let key = index_key(sub);
        redis.sadd::<_, _, ()>(&key, session_key).await?;
        redis
            .expire::<_, ()>(&key, INDEX_TTL.as_secs() as i64)
            .await
    }

    /// The kill switch's second step: which sessions belong to this user.
    pub async fn sessions(&self, sub: &str) -> Result<Vec<String>, redis::RedisError> {
        self.0.clone().smembers(index_key(sub)).await
    }

    // --- Feature Start ---
    // Every subject with at least one live session, for `GET /api/admin/sessions`
    // (ADR-0028). It counts members that still EXIST rather than the set's
    // cardinality, and that is the whole of the method: `forget_session` removes
    // a key on logout, but a session that merely expired leaves its key in the
    // set until the set's own TTL, so cardinality would report sessions that
    // ended — the one wrong answer a "who is connected" list must not give.
    // Reading only; nothing is written back, not even to prune.
    // --- Feature End ---
    // ponytail: SCAN walks the whole keyspace, which is mostly oauth2-proxy's own
    // sessions, and it runs on an admin request. If a site ever measures that
    // hurting, the upgrade is a set naming the subjects that have sessions —
    // which is a write on the decision path, so it is a decision and not a patch.
    pub async fn live(&self) -> Result<Vec<(String, usize)>, redis::RedisError> {
        let mut redis = self.0.clone();
        let mut cursor: u64 = 0;
        // SCAN may return the same key in two passes, so the sub is the key here
        // and not the position in a list.
        let mut found: HashMap<String, usize> = HashMap::new();
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{INDEX_PREFIX}*"))
                .arg("COUNT")
                .arg(200)
                .query_async(&mut redis)
                .await?;
            for key in keys {
                let Some(sub) = key.strip_prefix(INDEX_PREFIX) else {
                    continue;
                };
                let members: Vec<String> = redis.smembers(&key).await?;
                if members.is_empty() {
                    continue;
                }
                // One EXISTS for the whole set: it answers how many of the keys
                // named are present, and a set has no duplicates to inflate it.
                let alive: usize = redis::cmd("EXISTS")
                    .arg(&members)
                    .query_async(&mut redis)
                    .await?;
                if alive > 0 {
                    found.insert(sub.to_string(), alive);
                }
            }
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        Ok(found.into_iter().collect())
    }

    /// For /readyz. The index is the backend's only Redis use, so this is the
    /// whole of what "Redis is reachable" means to it.
    pub async fn ping(&self) -> Result<(), redis::RedisError> {
        redis::cmd("PING").exec_async(&mut self.0.clone()).await
    }

    /// The kill switch's third step, and the one that actually cuts access:
    /// oauth2-proxy answers 401 for a ticket whose key is gone, so the cache
    /// cannot be refilled behind us. An empty list is not a DEL — Redis
    /// refuses one with no keys, and "this user had no session here" is a
    /// normal outcome, not a failed kill.
    pub async fn drop_sessions(&self, keys: &[String]) -> Result<(), redis::RedisError> {
        if keys.is_empty() {
            return Ok(());
        }
        self.0.clone().del::<_, ()>(keys).await
    }

    /// The kill switch's last step, after the cache entries are gone.
    pub async fn forget(&self, sub: &str) -> Result<(), redis::RedisError> {
        self.0.clone().del::<_, ()>(index_key(sub)).await
    }

    /// Logout's last step. Only the browser that logged out leaves the index:
    /// `forget` would take the same user's other sessions with it, and a live
    /// session in no index is one the kill switch cannot find.
    pub async fn forget_session(&self, sub: &str, key: &str) -> Result<(), redis::RedisError> {
        self.0.clone().srem::<_, _, ()>(index_key(sub), key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kill switch reaches a live session only through this index, so its
    /// TTL has to outlast the cookie whose keys it holds. That number lives in
    /// another file and has moved once already (168 h to 10 h): a comment
    /// naming it goes stale in silence, and a TTL that is short means a
    /// revoked user keeps what the index could no longer find.
    #[test]
    fn the_index_outlasts_the_cookie_it_indexes() {
        let cfg = include_str!("../../oauth2-proxy/oauth2-proxy.cfg");
        let value = cfg
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("cookie_expire"))
            .and_then(|l| l.split('"').nth(1))
            .expect("oauth2-proxy.cfg sets cookie_expire");

        let mut expire = Duration::ZERO;
        let mut n = 0u64;
        for c in value.chars() {
            match c {
                '0'..='9' => n = n * 10 + u64::from(c.to_digit(10).unwrap()),
                'h' | 'm' | 's' => {
                    let unit = match c {
                        'h' => 3600,
                        'm' => 60,
                        _ => 1,
                    };
                    expire += Duration::from_secs(n * unit);
                    n = 0;
                }
                _ => panic!("cookie_expire is not a duration this test reads: {value}"),
            }
        }

        assert!(
            expire > Duration::ZERO,
            "cookie_expire read as zero: {value}"
        );
        assert!(
            INDEX_TTL >= expire,
            "INDEX_TTL {INDEX_TTL:?} is shorter than cookie_expire {expire:?}: \
             the kill switch would miss sessions that still authenticate"
        );
    }

    /// Builds a cookie the way oauth2-proxy does (docs/07, VERIFY (4)), so the
    /// test exercises the documented format rather than a convenient one.
    fn cookie(key: &str, secret: &str, signature: &str) -> String {
        let ticket = format!(
            "v2.{}.{}",
            URL_SAFE_NO_PAD.encode(key),
            URL_SAFE_NO_PAD.encode(secret)
        );
        format!("{}{signature}", URL_SAFE_NO_PAD.encode(ticket))
    }

    #[test]
    fn the_redis_key_comes_out_of_the_cookie() {
        let key = "_oauth2_proxy-d8f9514ab7f2dec2ee20adbcd026765c";
        assert_eq!(
            session_key(
                &cookie(key, "sekrit", "|1757000000|abcdef"),
                "_oauth2_proxy"
            )
            .as_deref(),
            Some(key)
        );
        // Measured: a cookie_refresh rotates the signature and leaves the handle
        // byte-identical, so an index written on the first miss stays valid.
        assert_eq!(
            session_key(
                &cookie(key, "sekrit", "|1757009999|999999"),
                "_oauth2_proxy"
            ),
            session_key(
                &cookie(key, "sekrit", "|1757000000|abcdef"),
                "_oauth2_proxy"
            ),
        );
        // And an unsigned cookie is the same ticket.
        assert_eq!(
            session_key(&cookie(key, "sekrit", ""), "_oauth2_proxy").as_deref(),
            Some(key)
        );
    }

    #[test]
    fn anything_that_is_not_one_of_our_keys_is_refused() {
        // The kill switch hands whatever comes out of here to DEL, so a value
        // that does not decode to a key of ours must not come out at all.
        for value in [
            "",
            "not-base64-at-all!!",
            &cookie("some-other-service-session", "s", "|1|a"),
            &cookie("_oauth2_proxy_but_not_quite", "s", "|1|a"),
            &URL_SAFE_NO_PAD.encode("v1.abc.def"),
            &URL_SAFE_NO_PAD.encode("no-version-prefix"),
        ] {
            assert!(
                session_key(value, "_oauth2_proxy").is_none(),
                "{value} must not reach DEL"
            );
        }
    }
}
