//! Shared TTL tag computation + expiry classification for ami-forge-managed
//! EC2 instances.
//!
//! Every ephemeral instance ami-forge launches (the Attic cache instance in
//! `attic.rs`, cluster-test nodes in `cluster_test.rs`) is tagged with both
//! [`TTL_HOURS_TAG_KEY`] (human-readable, informational) and
//! [`EXPIRES_AT_TAG_KEY`] — the absolute timestamp `reaper.rs` actually
//! filters on. Two call sites hand-computing that timestamp independently is
//! exactly how a writer/reader drift bug (task #204: ttl-hours set but never
//! read by the reaper) happens. This module is the single place that
//! computes the tag value at launch time and classifies it at reap time, so
//! writer and reader can never diverge again.

use anyhow::Context;
use chrono::{DateTime, Utc};

/// The tag key the reaper filters expiry on. Every writer MUST set this tag
/// (via [`compute_expires_at`]) for its instance to actually be reaped once
/// past TTL — a `ttl-hours` tag alone is informational only and is never
/// read by `reap_expired_instances`.
pub const EXPIRES_AT_TAG_KEY: &str = "ami-forge:expires-at";

/// The tag key recording the human-readable TTL window at launch time.
/// Informational — the reaper does not read this key directly, it only
/// reads [`EXPIRES_AT_TAG_KEY`].
pub const TTL_HOURS_TAG_KEY: &str = "ami-forge:ttl-hours";

/// The wire format both the writer ([`compute_expires_at`]) and the reader
/// ([`parse_expires_at`]) use for the `expires-at` tag value.
const TAG_TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

/// Compute the [`EXPIRES_AT_TAG_KEY`] tag value for an instance launched at
/// `launched_at`, with a TTL of `ttl_hours` hours.
///
/// Pure — no I/O, no clock reads. Launch sites pass `chrono::Utc::now()`;
/// tests pass a fixed instant so the expected string is exact and
/// reproducible.
pub fn compute_expires_at(launched_at: DateTime<Utc>, ttl_hours: i64) -> String {
    (launched_at + chrono::Duration::hours(ttl_hours))
        .format(TAG_TIME_FORMAT)
        .to_string()
}

/// Parse an `expires-at` tag value back into a UTC instant.
///
/// Accepts both RFC3339 (`+00:00` / `Z` offset forms) and the naive
/// `TAG_TIME_FORMAT` written by [`compute_expires_at`], mirroring the
/// fallback chain the reaper has always used.
pub fn parse_expires_at(expires_at_tag: &str) -> anyhow::Result<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(expires_at_tag)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(expires_at_tag, TAG_TIME_FORMAT)
                .map(|naive| naive.and_utc())
        })
        .with_context(|| format!("failed to parse expires-at tag value '{expires_at_tag}'"))
}

/// Whether a tagged instance's `expires-at` value places it before `now`.
///
/// `expires_at_tag` is the raw tag value as read off the instance (kept as
/// a plain `&str` rather than an AWS SDK type so this stays testable with a
/// fixture tag map — no EC2 client, no live AWS, needed).
pub fn is_expired(expires_at_tag: &str, now: DateTime<Utc>) -> anyhow::Result<bool> {
    Ok(now > parse_expires_at(expires_at_tag)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// A fixed "launched at" instant so every test in this module reasons
    /// about the exact same clock reading.
    fn fixed_launch_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 16, 12, 0, 0).unwrap()
    }

    #[test]
    fn compute_expires_at_adds_exact_ttl_hours() {
        // Given a fixed launch time and a fixed TTL, the computed
        // expires-at tag value must be the exact expected timestamp — this
        // is the value attic.rs/cluster_test.rs write at launch and the
        // one reaper.rs must be able to parse back out unchanged.
        let launched_at = fixed_launch_time();
        let expires_at = compute_expires_at(launched_at, 4);
        assert_eq!(expires_at, "2026-07-16T16:00:00Z");
    }

    #[test]
    fn compute_expires_at_matches_cluster_test_two_hour_ttl() {
        // cluster_test.rs launches test nodes with a 2h TTL.
        let launched_at = fixed_launch_time();
        let expires_at = compute_expires_at(launched_at, 2);
        assert_eq!(expires_at, "2026-07-16T14:00:00Z");
    }

    #[test]
    fn compute_expires_at_crosses_day_boundary() {
        let launched_at = Utc.with_ymd_and_hms(2026, 7, 16, 22, 30, 0).unwrap();
        let expires_at = compute_expires_at(launched_at, 4);
        assert_eq!(expires_at, "2026-07-17T02:30:00Z");
    }

    #[test]
    fn parse_expires_at_round_trips_the_written_format() {
        let launched_at = fixed_launch_time();
        let written = compute_expires_at(launched_at, 4);
        let parsed = parse_expires_at(&written).unwrap();
        assert_eq!(parsed, launched_at + chrono::Duration::hours(4));
    }

    #[test]
    fn parse_expires_at_accepts_rfc3339_with_offset() {
        // Defensive: a hand-edited or differently-sourced tag could carry a
        // real RFC3339 offset instead of the bare "Z" format we write.
        let parsed = parse_expires_at("2026-07-16T16:00:00+00:00").unwrap();
        assert_eq!(parsed, Utc.with_ymd_and_hms(2026, 7, 16, 16, 0, 0).unwrap());
    }

    #[test]
    fn parse_expires_at_errors_on_garbage() {
        let err = parse_expires_at("not-a-timestamp").unwrap_err();
        assert!(err.to_string().contains("failed to parse expires-at tag"));
    }

    #[test]
    fn is_expired_true_when_now_past_expiry() {
        let expires_at = "2026-07-16T16:00:00Z";
        let now = Utc.with_ymd_and_hms(2026, 7, 16, 16, 0, 1).unwrap();
        assert!(is_expired(expires_at, now).unwrap());
    }

    #[test]
    fn is_expired_false_when_now_before_expiry() {
        let expires_at = "2026-07-16T16:00:00Z";
        let now = Utc.with_ymd_and_hms(2026, 7, 16, 15, 59, 59).unwrap();
        assert!(!is_expired(expires_at, now).unwrap());
    }

    #[test]
    fn is_expired_false_at_exact_boundary() {
        // reaper.rs uses a strict `>` comparison, so an instance expiring
        // exactly "now" is not yet reaped — document that boundary here.
        let expires_at = "2026-07-16T16:00:00Z";
        let now = Utc.with_ymd_and_hms(2026, 7, 16, 16, 0, 0).unwrap();
        assert!(!is_expired(expires_at, now).unwrap());
    }

    // --- Fixture-tag-map tests: prove the reaper's filter logic matches
    // instances tagged the way attic.rs / cluster_test.rs actually tag
    // them, without touching AWS. ---

    /// Minimal stand-in for the `(key, value)` tag pairs EC2 returns —
    /// exercises the same lookup-by-key + is_expired path
    /// `reap_expired_instances` runs, against a plain fixture instead of an
    /// `aws_sdk_ec2::types::Tag` list.
    fn find_tag<'a>(tags: &'a [(&'a str, &'a str)], key: &str) -> Option<&'a str> {
        tags.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    #[test]
    fn reaper_filter_matches_attic_style_expired_instance() {
        // Shape written by attic.rs's tag_specifications: ttl-hours="4" +
        // expires-at=<computed>, launched 5 hours ago (past its 4h TTL).
        let launched_at = fixed_launch_time();
        let expires_at = compute_expires_at(launched_at, 4);
        let tags: Vec<(&str, &str)> = vec![
            ("ManagedBy", "pangea"),
            (TTL_HOURS_TAG_KEY, "4"),
            (EXPIRES_AT_TAG_KEY, expires_at.as_str()),
            ("ami-forge:purpose", "attic-cache"),
        ];

        let expires_at_tag =
            find_tag(&tags, EXPIRES_AT_TAG_KEY).expect("attic.rs always sets expires-at");
        let now = launched_at + chrono::Duration::hours(5);
        assert!(is_expired(expires_at_tag, now).unwrap());
    }

    #[test]
    fn reaper_filter_matches_cluster_test_style_unexpired_instance() {
        // Shape written by cluster_test.rs's tag_specifications: ttl-hours="2"
        // + expires-at=<computed>, checked 1 hour after launch (still valid).
        let launched_at = fixed_launch_time();
        let expires_at = compute_expires_at(launched_at, 2);
        let tags: Vec<(&str, &str)> = vec![
            ("ManagedBy", "pangea"),
            ("ClusterTestId", "test-abc123"),
            (TTL_HOURS_TAG_KEY, "2"),
            (EXPIRES_AT_TAG_KEY, expires_at.as_str()),
            ("ami-forge:purpose", "cluster-test"),
        ];

        let expires_at_tag =
            find_tag(&tags, EXPIRES_AT_TAG_KEY).expect("cluster_test.rs always sets expires-at");
        let now = launched_at + chrono::Duration::hours(1);
        assert!(!is_expired(expires_at_tag, now).unwrap());
    }

    #[test]
    fn reaper_filter_skips_instance_missing_expires_at_tag() {
        // This is the literal task-#204 failure mode: ttl-hours is present
        // but expires-at never got written, so the reaper's lookup finds
        // nothing and (per reaper.rs's `None` arm) the instance is skipped
        // with a warning rather than reaped or crashing.
        let tags: Vec<(&str, &str)> = vec![("ManagedBy", "pangea"), (TTL_HOURS_TAG_KEY, "4")];

        assert_eq!(find_tag(&tags, EXPIRES_AT_TAG_KEY), None);
    }
}
