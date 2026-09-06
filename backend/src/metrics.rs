// The four numbers Phase 6 asks the backend for — decision latency, error rate,
// cache hit rate and audit rows that never reached Postgres — in Prometheus
// text exposition format on GET /metrics.
//
// Hand-written rather than a client library: the format is four line shapes,
// and the counters here are the ones already named elsewhere in the code
// (`Deny::as_str`, `store::audit_dropped`), so a registry to hold them would be
// a second vocabulary for the same words.
//
// /metrics is unauthenticated and reachable from anything on the `core`
// network, like /healthz and /readyz — nginx proxies neither. That is why
// nothing here carries a user, a sub or an application slug: a label with one
// in it turns a scrape into a way to enumerate who is signed in and what they
// reach.

use crate::policy::{Decision, Deny};
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

/// Bucket edges in microseconds. N-01 (2 ms) and N-02 (10 ms) are edges rather
/// than something to interpolate between: the two latencies the product
/// promises are read straight off the exposition (`docs/06`).
const BUCKETS: [u64; 8] = [250, 500, 1_000, 2_000, 5_000, 10_000, 50_000, 250_000];
/// How the edges are written in the `le` label. Kept beside the numbers above
/// so a bucket cannot be added without its name.
const EDGES: [&str; 8] = [
    "0.00025", "0.0005", "0.001", "0.002", "0.005", "0.01", "0.05", "0.25",
];

static ALLOWED: AtomicU64 = AtomicU64::new(0);
/// Not a refusal: nobody has logged in yet, and nginx turns it into the login
/// redirect. It is counted so that the three outcomes add up to the number of
/// decisions — an error rate whose denominator quietly omits every fresh
/// browser is one nobody can read.
static UNAUTHENTICATED: AtomicU64 = AtomicU64::new(0);
static DENIED: [AtomicU64; Deny::ALL.len()] = [const { AtomicU64::new(0) }; Deny::ALL.len()];
static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static LATENCY: [AtomicU64; BUCKETS.len() + 1] = [const { AtomicU64::new(0) }; BUCKETS.len() + 1];
static LATENCY_MICROS: AtomicU64 = AtomicU64::new(0);

pub fn outcome(decision: Decision) {
    match decision {
        Decision::Allow => &ALLOWED,
        // A reason with no counter is one `Deny::ALL` was not told about. It
        // costs a series, and it must not cost a request: this is the response
        // path of every single decision.
        Decision::Deny(reason) => match DENIED.get(reason as usize) {
            Some(counter) => counter,
            None => return,
        },
    }
    .fetch_add(1, Relaxed);
}

pub fn unauthenticated() {
    UNAUTHENTICATED.fetch_add(1, Relaxed);
}

pub fn cache(hit: bool) {
    if hit { &HITS } else { &MISSES }.fetch_add(1, Relaxed);
}

pub fn observe(elapsed: Duration) {
    let micros = elapsed.as_micros() as u64;
    LATENCY_MICROS.fetch_add(micros, Relaxed);
    let bucket = BUCKETS.iter().position(|edge| micros <= *edge);
    LATENCY[bucket.unwrap_or(BUCKETS.len())].fetch_add(1, Relaxed);
}

pub fn render() -> String {
    let mut out = String::with_capacity(2048);
    out.push_str(
        "# HELP openberat_decision_total Authorisation decisions, by outcome and reason.\n\
         # TYPE openberat_decision_total counter\n",
    );
    let _ = writeln!(
        out,
        "openberat_decision_total{{decision=\"allow\",reason=\"allowed\"}} {}",
        ALLOWED.load(Relaxed)
    );
    let _ = writeln!(
        out,
        "openberat_decision_total{{decision=\"unauthenticated\",reason=\"no_session\"}} {}",
        UNAUTHENTICATED.load(Relaxed)
    );
    for reason in Deny::ALL {
        let _ = writeln!(
            out,
            "openberat_decision_total{{decision=\"deny\",reason=\"{}\"}} {}",
            reason.as_str(),
            DENIED[reason as usize].load(Relaxed)
        );
    }

    out.push_str(
        "# HELP openberat_decision_cache_total Decision cache lookups.\n\
         # TYPE openberat_decision_cache_total counter\n",
    );
    let _ = writeln!(
        out,
        "openberat_decision_cache_total{{result=\"hit\"}} {}\n\
         openberat_decision_cache_total{{result=\"miss\"}} {}",
        HITS.load(Relaxed),
        MISSES.load(Relaxed)
    );

    out.push_str(
        "# HELP openberat_decision_duration_seconds Time spent answering /decide.\n\
         # TYPE openberat_decision_duration_seconds histogram\n",
    );
    // Prometheus buckets are cumulative: each line counts everything at or
    // under its edge, not the slice between two edges.
    let mut below = 0;
    for (edge, count) in EDGES.iter().zip(&LATENCY) {
        below += count.load(Relaxed);
        let _ = writeln!(
            out,
            "openberat_decision_duration_seconds_bucket{{le=\"{edge}\"}} {below}"
        );
    }
    below += LATENCY[BUCKETS.len()].load(Relaxed);
    let micros = LATENCY_MICROS.load(Relaxed);
    let _ = writeln!(
        out,
        "openberat_decision_duration_seconds_bucket{{le=\"+Inf\"}} {below}\n\
         openberat_decision_duration_seconds_sum {}.{:06}\n\
         openberat_decision_duration_seconds_count {below}",
        micros / 1_000_000,
        micros % 1_000_000
    );

    // --- Feature Start ---
    // The audit record is the product's evidence, and the one way it is lost
    // quietly is a full channel or a failed insert — both of which answer the
    // user normally. This counter is the only outside sign it happened.
    // --- Feature End ---
    let _ = writeln!(
        out,
        "# HELP openberat_audit_dropped_total Audit summaries that never reached Postgres.\n\
         # TYPE openberat_audit_dropped_total counter\n\
         openberat_audit_dropped_total {}",
        crate::store::audit_dropped()
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_latency_lands_in_the_first_bucket_at_or_above_it() {
        // Cumulative, so the count under 2 ms is the count under 10 ms too —
        // the property N-01 and N-02 are read with.
        observe(Duration::from_micros(1_500));
        observe(Duration::from_secs(3));
        let exposition = render();
        let at = |edge: &str| {
            exposition
                .lines()
                .find_map(|line| {
                    line.strip_prefix(&format!(
                        "openberat_decision_duration_seconds_bucket{{le=\"{edge}\"}}"
                    ))?
                    .trim()
                    .parse::<u64>()
                    .ok()
                })
                .expect("bucket")
        };
        assert_eq!(at("0.001"), 0, "1.5 ms is not under 1 ms");
        assert_eq!(at("0.002"), 1);
        assert_eq!(at("0.01"), 1, "and stays counted in every wider bucket");
        assert_eq!(
            at("+Inf"),
            2,
            "3 s falls past the last edge, not off the end"
        );
        assert!(exposition.contains("openberat_decision_duration_seconds_sum 3.001500"));
    }
}
