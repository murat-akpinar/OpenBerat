// The decision cache (docs/05, "Decision cache"). Not an optimisation: steps
// 2-12 of the flow repeat on every asset of every page, so without this N-01 is
// unreachable and the oauth2-proxy hop runs 50 times for one page load.
//
// What is cached is the identity and the rule list, not the verdict. The
// matched pattern cannot be part of the key — finding it *is* the query the
// cache exists to avoid — so every request is evaluated against the full rule
// list on arrival and a deny can never be skipped by two paths colliding on one
// key.

use crate::policy::{Decision, Rule};
use crate::store::{Audit, AuditEvent};
use axum::http::HeaderValue;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Identity and rules go stale together, so there is one number. It is half of
/// the N-03 revocation budget; the other half is oauth2-proxy's `cookie_refresh`
/// (ADR-0006, ADR-0016).
// ponytail: a constant, not configuration. It becomes a setting the first time
// somebody needs a different N-03 trade, and not before.
pub const TTL: Duration = Duration::from_secs(30);

/// One user cannot produce unbounded entries: their cookie is one value and
/// they can only reach the applications that exist.
const CAPACITY: usize = 10_000;

/// Must match `cookie_name` in `oauth2-proxy/oauth2-proxy.cfg`. A mismatch is
/// survivable rather than fatal — see `Key::new`.
pub const COOKIE_NAME: &str = "_oauth2_proxy";

/// The session cookie's value, for deriving the oauth2-proxy session key
/// (ADR-0019). A **chunked** session returns None: the measured cookie is a
/// fixed 192 bytes and never chunks (docs/07), so a chunked one means something
/// changed underneath us, and guessing how to reassemble a ticket would produce
/// a key the kill switch cannot use.
pub fn session_cookie(cookie_header: Option<&str>) -> Option<&str> {
    cookie_header?.split(';').find_map(|cookie| {
        let (name, value) = cookie.split_once('=')?;
        (name.trim() == COOKIE_NAME).then_some(value)
    })
}

const FILL_SHARDS: usize = 16;

/// The verified identity, as the headers nginx lifts off a 200 (`docs/02`,
/// response contract). Kept in that form because that is the only form it is
/// ever used in.
#[derive(Debug)]
pub struct Identity {
    pub sub: HeaderValue,
    pub username: HeaderValue,
    pub email: HeaderValue,
    pub groups: HeaderValue,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Key {
    cookie: [u8; 32],
    slug: String,
}

impl Key {
    // --- Feature Start ---
    // Only the oauth2-proxy session cookie is hashed, never the whole Cookie
    // header: applications set their own cookies on the shared domain
    // (ADR-0015), and hashing the header would mint a new key every time one of
    // them changed, taking the hit rate N-01 depends on with it.
    //
    // And no cookie means no key. If COOKIE_NAME ever stops matching
    // oauth2-proxy's configuration, hashing what was found would give every
    // user the same key, and the first user to fill an entry would hand their
    // identity to everyone else on it. Returning None costs a cache miss per
    // request; the alternative costs the product.
    // --- Feature End ---
    pub fn new(cookie_header: Option<&str>, slug: &str) -> Option<Key> {
        let mut hasher = Sha256::new();
        let mut found = false;
        for cookie in cookie_header?.split(';') {
            let Some((name, value)) = cookie.split_once('=') else {
                continue;
            };
            let name = name.trim();
            // oauth2-proxy splits an oversized session cookie into `_0`, `_1`…
            // The suffix has to be digits: a client can set any cookie it likes
            // on the shared domain (ADR-0015), and `_oauth2_proxy_anything`
            // would otherwise let it move its own cache key on every request.
            let chunk = name
                .strip_prefix(COOKIE_NAME)
                .and_then(|rest| rest.strip_prefix('_'))
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
            if name == COOKIE_NAME || chunk {
                hasher.update(name.as_bytes());
                hasher.update(value.as_bytes());
                found = true;
            }
        }
        found.then(|| Key {
            cookie: hasher.finalize().into(),
            slug: slug.to_string(),
        })
    }
}

/// What a hit hands back. Both are shared rather than copied: a page of assets
/// is 50 hits on the same entry.
#[derive(Clone)]
pub struct Cached {
    pub identity: Arc<Identity>,
    pub rules: Arc<Vec<Rule>>,
    pub enabled: bool,
    pub application_id: Option<Uuid>,
}

/// One outcome's running total inside a live entry. Written out as a single
/// `audit_event` row when the entry leaves the cache (docs/02, "Audit
/// granularity").
struct Counters {
    count: i32,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    first_path: String,
    src_ip: Option<IpAddr>,
    request_id: Option<String>,
    // ponytail: one hash per distinct path, so a user walking 50k paths inside
    // one TTL costs 400 KB. Swap for an estimator if that ever shows up.
    distinct: HashSet<u64>,
}

struct Entry {
    sub: String,
    slug: String,
    cached: Cached,
    inserted: Instant,
    counters: HashMap<Decision, Counters>,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<Key, Entry>,
    /// Insertion order, for the capacity bound. Keys removed from `entries`
    /// are left here and skipped when they surface.
    order: VecDeque<Key>,
    /// Which keys belong to whom, so logout and the kill switch drop one user's
    /// entries rather than the whole cache — which would be self-DoS (docs/05).
    by_sub: HashMap<String, HashSet<Key>>,
}

pub struct Cache {
    inner: Mutex<Inner>,
    /// ponytail: 16 fill locks rather than one per key — nothing to clean up,
    /// and two different keys hashing to the same shard only serialise their
    /// misses. Single-flight for the *same* key is what matters and is exact.
    fill: Vec<tokio::sync::Mutex<()>>,
    audit: Audit,
}

impl Cache {
    pub fn new(audit: Audit) -> Cache {
        Cache {
            inner: Mutex::new(Inner::default()),
            fill: (0..FILL_SHARDS)
                .map(|_| tokio::sync::Mutex::new(()))
                .collect(),
            audit,
        }
    }

    pub fn get(&self, key: &Key) -> Option<Cached> {
        let inner = self.inner.lock().unwrap();
        let entry = inner.entries.get(key)?;
        (entry.inserted.elapsed() < TTL).then(|| entry.cached.clone())
    }

    /// Held across the whole miss, so fifty requests arriving together on an
    /// expired key produce one refresh and not fifty.
    pub async fn fill_lock(&self, key: &Key) -> tokio::sync::MutexGuard<'_, ()> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        self.fill[hasher.finish() as usize % FILL_SHARDS]
            .lock()
            .await
    }

    pub fn insert(&self, key: Key, sub: String, cached: Cached) {
        let slug = key.slug.clone();
        let mut inner = self.inner.lock().unwrap();
        // Replacing an entry is still an exit road for the one being replaced.
        if let Some(old) = inner.entries.remove(&key) {
            forget_sub(&mut inner, &old.sub, &key);
            self.flush(old);
        }
        inner
            .by_sub
            .entry(sub.clone())
            .or_default()
            .insert(key.clone());
        inner.order.push_back(key.clone());
        inner.entries.insert(
            key,
            Entry {
                sub,
                slug: slug.clone(),
                cached,
                inserted: Instant::now(),
                counters: HashMap::new(),
            },
        );
        while inner.entries.len() > CAPACITY {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            if let Some(entry) = inner.entries.remove(&oldest) {
                forget_sub(&mut inner, &entry.sub, &oldest);
                self.flush(entry);
            }
        }
    }

    /// Counts one decision against a live entry. A request whose key was never
    /// cached has nowhere to count, and writes its own row instead.
    pub fn count(
        &self,
        key: &Key,
        decision: Decision,
        path: &str,
        src_ip: Option<IpAddr>,
        request_id: Option<String>,
    ) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let Some(entry) = inner.entries.get_mut(key) else {
            return false;
        };
        let now = Utc::now();
        let mut hasher = DefaultHasher::new();
        path.hash(&mut hasher);
        let counters = entry.counters.entry(decision).or_insert_with(|| Counters {
            count: 0,
            first_seen: now,
            last_seen: now,
            first_path: path.to_string(),
            src_ip,
            request_id,
            distinct: HashSet::new(),
        });
        counters.count += 1;
        counters.last_seen = now;
        counters.distinct.insert(hasher.finish());
        true
    }

    /// TTL expiry — the road every entry takes if nothing else happens first.
    pub fn sweep(&self) {
        let expired: Vec<Key> = {
            let inner = self.inner.lock().unwrap();
            inner
                .entries
                .iter()
                .filter(|(_, e)| e.inserted.elapsed() >= TTL)
                .map(|(k, _)| k.clone())
                .collect()
        };
        for key in expired {
            self.evict(&key);
        }
    }

    /// Logout and the kill switch (ADR-0019). Only this user's entries: dropping
    /// the whole cache would be self-DoS.
    pub fn drop_sub(&self, sub: &str) {
        let keys: Vec<Key> = {
            let inner = self.inner.lock().unwrap();
            inner
                .by_sub
                .get(sub)
                .into_iter()
                .flatten()
                .cloned()
                .collect()
        };
        for key in keys {
            self.evict(&key);
        }
    }

    /// Shutdown. Without it up to one TTL of summaries is lost on every restart
    /// (docs/02, "Audit granularity"); a hard crash still loses them.
    pub fn flush_all(&self) {
        let keys: Vec<Key> = {
            let inner = self.inner.lock().unwrap();
            inner.entries.keys().cloned().collect()
        };
        for key in keys {
            self.evict(&key);
        }
    }

    // --- Feature Start ---
    // Every road out of the cache comes through here, because dropping an entry
    // without writing its counters deletes audit silently — and the kill-switch
    // road would lose exactly the user under incident response (docs/02).
    // --- Feature End ---
    fn evict(&self, key: &Key) {
        let entry = {
            let mut inner = self.inner.lock().unwrap();
            let Some(entry) = inner.entries.remove(key) else {
                return;
            };
            forget_sub(&mut inner, &entry.sub, key);
            entry
        };
        self.flush(entry);
    }

    /// Ages an entry past its TTL without a 30-second sleep in the test suite.
    #[cfg(test)]
    pub fn expire_for_test(&self, key: &Key) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(key) {
            entry.inserted -= TTL;
        }
    }

    fn flush(&self, entry: Entry) {
        for (decision, counters) in entry.counters {
            self.audit.record(AuditEvent {
                application_id: entry.cached.application_id,
                application_slug: entry.slug.clone(),
                actor_sub: entry.sub.clone(),
                actor_name: header_string(&entry.cached.identity.username),
                decision,
                count: counters.count,
                first_seen: counters.first_seen,
                last_seen: counters.last_seen,
                distinct_path: counters.distinct.len() as i32,
                first_path: counters.first_path,
                src_ip: counters.src_ip,
                request_id: counters.request_id,
            });
        }
    }
}

fn forget_sub(inner: &mut Inner, sub: &str, key: &Key) {
    if let Some(keys) = inner.by_sub.get_mut(sub) {
        keys.remove(key);
        if keys.is_empty() {
            inner.by_sub.remove(sub);
        }
    }
}

fn header_string(value: &HeaderValue) -> Option<String> {
    let value = value.to_str().ok()?;
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Deny, Effect};
    use crate::store::audit_channel;

    fn identity(sub: &str) -> Arc<Identity> {
        Arc::new(Identity {
            sub: HeaderValue::from_str(sub).unwrap(),
            username: HeaderValue::from_static("labuser"),
            email: HeaderValue::from_static("labuser@example.local"),
            groups: HeaderValue::from_static("OpenBerat-Finance"),
        })
    }

    fn cached() -> Cached {
        Cached {
            identity: identity("sub-labuser"),
            rules: Arc::new(vec![Rule {
                effect: Effect::Allow,
                path_pattern: String::new(),
                expires_at: None,
            }]),
            enabled: true,
            application_id: None,
        }
    }

    fn key(cookie: &str, slug: &str) -> Key {
        Key::new(Some(cookie), slug).expect("a session cookie is present")
    }

    // --- the cookie half of the key ---

    #[test]
    fn only_the_session_cookie_is_hashed() {
        // An application setting its own cookie on the shared domain must not
        // move the key, or the hit rate N-01 depends on collapses.
        let plain = key("_oauth2_proxy=abc", "finance");
        assert_eq!(plain, key("_oauth2_proxy=abc; app_pref=dark", "finance"));
        assert_eq!(plain, key("other=1; _oauth2_proxy=abc; last=2", "finance"));
        assert_ne!(plain, key("_oauth2_proxy=def", "finance"));
        // The same session on two applications is two decisions.
        assert_ne!(plain, key("_oauth2_proxy=abc", "payroll"));
    }

    #[test]
    fn no_session_cookie_means_no_key() {
        // The failure this guards against is COOKIE_NAME drifting from
        // oauth2-proxy's configuration: hashing what was found would give every
        // user the same key, and the first to fill an entry would hand their
        // identity to everyone else. A miss per request is the cheap failure.
        assert!(Key::new(None, "finance").is_none());
        assert!(Key::new(Some(""), "finance").is_none());
        assert!(Key::new(Some("app_pref=dark; other=1"), "finance").is_none());
        assert!(Key::new(Some("_oauth2_proxy_lookalike=abc"), "finance").is_none());
        // A chunked session cookie is still the session cookie.
        assert!(Key::new(Some("_oauth2_proxy_0=a; _oauth2_proxy_1=b"), "finance").is_some());
    }

    // --- exit roads ---

    /// Every road out has to flush, so each one is walked and the summary is
    /// read back off the channel.
    fn walk_exit_road(road: impl Fn(&Cache, &Key)) -> Vec<AuditEvent> {
        let (audit, mut queue) = audit_channel(16);
        let cache = Cache::new(audit);
        let k = key("_oauth2_proxy=abc", "finance");
        cache.insert(k.clone(), "sub-labuser".to_string(), cached());
        cache.count(&k, Decision::Allow, "/a", None, None);
        cache.count(&k, Decision::Allow, "/b", None, None);
        cache.count(
            &k,
            Decision::Deny(Deny::ExplicitDeny),
            "/admin/",
            None,
            None,
        );
        assert!(
            queue.try_recv().is_err(),
            "nothing is written while the entry lives"
        );
        road(&cache, &k);
        let mut written = Vec::new();
        while let Ok(event) = queue.try_recv() {
            written.push(event);
        }
        written
    }

    /// One way an entry can leave the cache.
    type ExitRoad = fn(&Cache, &Key);

    #[test]
    fn every_road_out_of_the_cache_flushes_its_counters() {
        let roads: [(&str, ExitRoad); 3] = [
            ("logout / kill switch", |c, _| c.drop_sub("sub-labuser")),
            ("shutdown", |c, _| c.flush_all()),
            ("replaced by a refill", |c, k| {
                c.insert(k.clone(), "sub-labuser".to_string(), cached())
            }),
        ];
        for (road, walk) in roads {
            let written = walk_exit_road(walk);
            // One row per outcome: one allow, one per distinct deny reason.
            assert_eq!(written.len(), 2, "{road}");
            let allow = written
                .iter()
                .find(|e| e.decision == Decision::Allow)
                .expect(road);
            assert_eq!(allow.count, 2, "{road}");
            assert_eq!(allow.distinct_path, 2, "{road}: /a and /b");
            assert_eq!(
                allow.first_path, "/a",
                "{road}: the first request folded in"
            );
            let deny = written
                .iter()
                .find(|e| e.decision == Decision::Deny(Deny::ExplicitDeny))
                .expect(road);
            assert_eq!(deny.count, 1, "{road}");
        }
    }

    #[test]
    fn an_expired_entry_is_a_miss_and_its_counters_are_written() {
        let (audit, mut queue) = audit_channel(16);
        let cache = Cache::new(audit);
        let k = key("_oauth2_proxy=abc", "finance");
        cache.insert(k.clone(), "sub-labuser".to_string(), cached());
        cache.count(&k, Decision::Allow, "/a", None, None);
        assert!(cache.get(&k).is_some());

        // The clock is the one thing policy.rs is not allowed to read, so the
        // cache is where a TTL test has to live. Reaching in beats sleeping 30 s.
        cache.expire_for_test(&k);
        assert!(
            cache.get(&k).is_none(),
            "an entry past its TTL is not a hit"
        );
        assert!(
            queue.try_recv().is_err(),
            "and is not written until it is swept"
        );
        cache.sweep();
        assert_eq!(queue.try_recv().unwrap().count, 1);
    }

    #[test]
    fn the_bound_evicts_the_entry_closest_to_expiry() {
        let (audit, mut queue) = audit_channel(CAPACITY * 2);
        let cache = Cache::new(audit);
        let first = key("_oauth2_proxy=first", "finance");
        cache.insert(first.clone(), "sub-first".to_string(), cached());
        cache.count(&first, Decision::Allow, "/a", None, None);
        for i in 0..CAPACITY {
            let k = key(&format!("_oauth2_proxy=filler{i}"), "finance");
            cache.insert(k, format!("sub-{i}"), cached());
        }
        // Under one uniform TTL, oldest-inserted is also closest to death, so
        // insertion order is the eviction order — an LRU would evict a fresher
        // entry that had simply not been asked for yet.
        assert!(cache.get(&first).is_none(), "the oldest entry went first");
        assert_eq!(
            queue.try_recv().unwrap().count,
            1,
            "and took its counters with it"
        );
    }
}
