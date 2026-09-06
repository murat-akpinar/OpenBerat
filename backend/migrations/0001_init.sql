-- Initial schema: application, entitlement, audit_event
-- known_user and entitlement.conditions are NOT in v1 (v2 — docs/02 "Data model")
-- audit_event STARTS with its summary columns: count, first_seen, last_seen,
-- distinct_path, and first_path/src_ip/request_id from the first request folded
-- into the row (no user_agent — docs/02 "Data model"). Partitioned by month, so
-- the PK is (id, ts) — Postgres requires the partition key in the primary key.
-- A DEFAULT partition is created here too: without one an INSERT for an
-- uncovered month errors, and audit writes fail silently off the request path.
-- Adding any of this later is a breaking change (CONTRIBUTING.md audit rule).
-- entitlement.subject_id holds the AD group NAME, not a SID (ADR-0008).
-- For the columns see docs/02-architecture.md "Data model"

create table application (
    id                uuid primary key default gen_random_uuid(),
    -- --- Feature Start ---
    -- slug and external_hostname are interpolated into generated nginx server
    -- blocks (ADR-0011), so a value carrying whitespace, a newline or a
    -- semicolon is config injection. The constraint lives here rather than only
    -- in the admin API because the generator reads the table, not the API.
    slug              text not null unique
                          check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    external_hostname text not null unique
                          check (external_hostname ~ '^[a-z0-9]+([.-][a-z0-9]+)*$'),
    -- --- Feature End ---
    name              text not null check (name <> ''),
    icon              text,
    -- Only the shape is checked here; loopback, link-local and metadata
    -- addresses are rejected by the admin API when applications become
    -- creatable (TODO.md Phase 4).
    upstream_url      text not null check (upstream_url ~ '^https?://[^[:space:]]+$'),
    enabled           boolean not null default true,
    created_at        timestamptz not null default now()
);

create table entitlement (
    id             uuid primary key default gen_random_uuid(),
    -- NULL means every application: the wildcard of docs/05 rule 4.
    application_id uuid references application (id) on delete cascade,
    subject_type   text not null check (subject_type in ('ad_group', 'user')),
    -- An AD group name (ADR-0008) or a Keycloak sub, per subject_type.
    subject_id     text not null check (subject_id <> ''),
    effect         text not null check (effect in ('allow', 'deny')),
    -- Empty means the whole application; '/admin/*' means that path only.
    -- Matching happens on the normalised path in policy.rs (docs/05).
    path_pattern   text not null default '' check (path_pattern = '' or path_pattern ~ '^/'),
    expires_at     timestamptz,
    created_at     timestamptz not null default now(),
    -- NULLS NOT DISTINCT, or the wildcard rules — the dangerous ones — are the
    -- only rules a double-clicked admin form can duplicate.
    unique nulls not distinct (application_id, subject_type, subject_id, effect, path_pattern)
);

-- The decision path asks "the rules for these groups", so subject_id leads.
create index entitlement_subject_idx on entitlement (subject_id, application_id);

-- --- Feature Start ---
-- No foreign key to application, and the slug is denormalised into the row:
-- deleting an application must not take the record of who reached it with it.
-- application_id is nullable for the same reason the slug is not — a decision
-- for an unknown X-App-Slug never had a row to point at, and that denial is
-- exactly the one worth keeping.
-- --- Feature End ---
create table audit_event (
    id                uuid not null default gen_random_uuid(),
    ts                timestamptz not null default now(),
    actor_sub         text not null,
    actor_name        text,
    application_id    uuid,
    application_slug  text not null,
    decision          text not null check (decision in ('allow', 'deny')),
    reason            text not null,
    -- One row summarises one cache entry's requests for one outcome
    -- (docs/02 "Audit granularity"); a row folding zero of them is a bug.
    count             integer not null check (count > 0),
    first_seen        timestamptz not null,
    last_seen         timestamptz not null,
    distinct_path     integer not null default 0 check (distinct_path >= 0),
    -- Of the FIRST request folded into the row; the per-request stream is
    -- stdout (F-23).
    first_path        text not null,
    src_ip            inet,
    request_id        text,
    primary key (id, ts)
) partition by range (ts);

-- ponytail: the DEFAULT partition is the only one. Monthly partitions and their
-- maintenance are the N-04 retention job (TODO.md Phase 6); until it exists
-- every row lands here, and attaching a month later means detaching the
-- default, moving that month's rows out and reattaching it.
create table audit_event_default partition of audit_event default;

create index audit_event_ts_idx on audit_event (ts desc);
create index audit_event_actor_idx on audit_event (actor_sub, ts desc);
