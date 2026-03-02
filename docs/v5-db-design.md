# v5 DB Design (Continuous STG Pentest)

## Goal

v5 extends the current graph-native schema (`nodes`, `edges`, `artifacts`) so the system can:

1. Run continuously (scheduled or event-triggered)
2. Keep an auditable execution history
3. Track finding lifecycle over time
4. Produce time-series risk snapshots

This version is intentionally additive. It does not rewrite the core graph model.

## Scope and Assumptions

1. v5 assumes one logical target environment per DB (single-tenant DB).
2. `nodes.natural_key` uniqueness remains global as-is.
3. Existing ingestion and query behavior must keep working without modification.

Multi-tenant graph partitioning is deferred to a future major version.

## Core Design Principles

1. Add operational tables, do not break graph tables.
2. Preserve lineage from `run -> action -> execution -> artifact -> node/edge`.
3. Make queue processing safe for concurrent workers.
4. Model finding state transitions explicitly (not just current state).

## New Tables

### 1) `engagements`

Represents a long-lived assessment context (for STG continuous testing).

```sql
CREATE TABLE IF NOT EXISTS engagements (
  id                 TEXT PRIMARY KEY,
  name               TEXT NOT NULL,
  environment        TEXT NOT NULL DEFAULT 'stg',   -- stg|dev|prod-like
  scope_json         TEXT NOT NULL DEFAULT '{}',    -- targets, exclusions
  policy_json        TEXT NOT NULL DEFAULT '{}',    -- safety limits
  schedule_cron      TEXT,                          -- optional scheduler hint
  status             TEXT NOT NULL DEFAULT 'active',-- active|paused|archived
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_engagements_status ON engagements(status);
```

### 2) `runs`

Represents one execution cycle (manual/scheduled/event).

```sql
CREATE TABLE IF NOT EXISTS runs (
  id                 TEXT PRIMARY KEY,
  engagement_id      TEXT NOT NULL,
  trigger_kind       TEXT NOT NULL,                 -- manual|schedule|event
  trigger_ref        TEXT,                          -- cron id, webhook id, etc
  status             TEXT NOT NULL,                 -- queued|running|succeeded|failed|canceled
  started_at         TEXT,
  finished_at        TEXT,
  summary_json       TEXT NOT NULL DEFAULT '{}',
  created_at         TEXT NOT NULL,
  FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_runs_engagement_created ON runs(engagement_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
```

### 3) `action_queue`

Queue of proposed executable actions.

```sql
CREATE TABLE IF NOT EXISTS action_queue (
  id                 TEXT PRIMARY KEY,
  engagement_id      TEXT NOT NULL,
  run_id             TEXT,
  parent_action_id   TEXT,
  kind               TEXT NOT NULL,                 -- nmap_scan|ffuf_discovery|...
  priority           INTEGER NOT NULL DEFAULT 100,  -- smaller is higher
  dedupe_key         TEXT NOT NULL,                 -- semantic identity
  params_json        TEXT NOT NULL DEFAULT '{}',
  state              TEXT NOT NULL,                 -- queued|running|succeeded|failed|canceled|skipped
  attempt_count      INTEGER NOT NULL DEFAULT 0,
  max_attempts       INTEGER NOT NULL DEFAULT 3,
  available_at       TEXT NOT NULL,
  lease_owner        TEXT,
  lease_expires_at   TEXT,
  last_error         TEXT,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL,
  FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
  FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE SET NULL,
  FOREIGN KEY (parent_action_id) REFERENCES action_queue(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_action_queue_poll
  ON action_queue(state, available_at, priority, created_at);
CREATE INDEX IF NOT EXISTS idx_action_queue_engagement_state
  ON action_queue(engagement_id, state, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_action_queue_active_dedupe
  ON action_queue(engagement_id, dedupe_key)
  WHERE state IN ('queued', 'running');
```

### 4) `action_executions`

Stores execution attempts and outcomes for queue items.

```sql
CREATE TABLE IF NOT EXISTS action_executions (
  id                 TEXT PRIMARY KEY,
  action_id          TEXT NOT NULL,
  run_id             TEXT,
  executor           TEXT NOT NULL,                 -- worker identity
  command            TEXT,                          -- optional concrete command
  input_json         TEXT NOT NULL DEFAULT '{}',
  output_json        TEXT NOT NULL DEFAULT '{}',
  stdout_artifact_id TEXT,
  stderr_artifact_id TEXT,
  exit_code          INTEGER,
  error_type         TEXT,
  error_message      TEXT,
  started_at         TEXT NOT NULL,
  finished_at        TEXT,
  duration_ms        INTEGER,
  FOREIGN KEY (action_id) REFERENCES action_queue(id) ON DELETE CASCADE,
  FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE SET NULL,
  FOREIGN KEY (stdout_artifact_id) REFERENCES artifacts(id) ON DELETE SET NULL,
  FOREIGN KEY (stderr_artifact_id) REFERENCES artifacts(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_action_exec_action_started ON action_executions(action_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_action_exec_run_started ON action_executions(run_id, started_at DESC);
```

### 5) `findings`

Operational finding entity with lifecycle state.

```sql
CREATE TABLE IF NOT EXISTS findings (
  id                 TEXT PRIMARY KEY,
  engagement_id      TEXT NOT NULL,
  canonical_key      TEXT NOT NULL,                 -- dedupe identity across runs
  node_id            TEXT,                          -- usually vulnerability node
  title              TEXT NOT NULL,
  severity           TEXT NOT NULL,                 -- critical|high|medium|low|info
  confidence         TEXT NOT NULL,                 -- high|medium|low
  state              TEXT NOT NULL,                 -- open|accepted_risk|false_positive|fixed|suppressed
  state_reason       TEXT,
  owner              TEXT,
  ticket_ref         TEXT,
  first_seen_run_id  TEXT,
  last_seen_run_id   TEXT,
  first_seen_at      TEXT NOT NULL,
  last_seen_at       TEXT NOT NULL,
  sla_due_at         TEXT,
  attrs_json         TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
  FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE SET NULL,
  FOREIGN KEY (first_seen_run_id) REFERENCES runs(id) ON DELETE SET NULL,
  FOREIGN KEY (last_seen_run_id) REFERENCES runs(id) ON DELETE SET NULL,
  UNIQUE (engagement_id, canonical_key)
);
CREATE INDEX IF NOT EXISTS idx_findings_engagement_state_sev
  ON findings(engagement_id, state, severity, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_node ON findings(node_id);
```

### 6) `finding_events`

Immutable history of finding changes.

```sql
CREATE TABLE IF NOT EXISTS finding_events (
  id                 TEXT PRIMARY KEY,
  finding_id         TEXT NOT NULL,
  run_id             TEXT,
  event_type         TEXT NOT NULL,                 -- discovered|reopened|updated|state_changed|closed
  before_json        TEXT NOT NULL DEFAULT '{}',
  after_json         TEXT NOT NULL DEFAULT '{}',
  artifact_id        TEXT,
  created_at         TEXT NOT NULL,
  FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
  FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE SET NULL,
  FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_events_finding_created
  ON finding_events(finding_id, created_at DESC);
```

### 7) `risk_snapshots`

Time-series risk metrics for dashboards and trend alerts.

```sql
CREATE TABLE IF NOT EXISTS risk_snapshots (
  id                   TEXT PRIMARY KEY,
  engagement_id        TEXT NOT NULL,
  run_id               TEXT,
  score                REAL NOT NULL,
  open_critical        INTEGER NOT NULL DEFAULT 0,
  open_high            INTEGER NOT NULL DEFAULT 0,
  open_medium          INTEGER NOT NULL DEFAULT 0,
  open_low             INTEGER NOT NULL DEFAULT 0,
  open_info            INTEGER NOT NULL DEFAULT 0,
  open_total           INTEGER NOT NULL DEFAULT 0,
  attack_path_count    INTEGER NOT NULL DEFAULT 0,
  exposed_cred_count   INTEGER NOT NULL DEFAULT 0,
  model_version        TEXT,
  attrs_json           TEXT NOT NULL DEFAULT '{}',
  created_at           TEXT NOT NULL,
  FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
  FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_risk_snapshots_engagement_created
  ON risk_snapshots(engagement_id, created_at DESC);
```

## Changes to Existing Tables

Add lineage columns without changing current constraints:

```sql
ALTER TABLE scans ADD COLUMN engagement_id TEXT REFERENCES engagements(id) ON DELETE SET NULL;
ALTER TABLE scans ADD COLUMN run_id TEXT REFERENCES runs(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_scans_engagement_started ON scans(engagement_id, started_at DESC);

ALTER TABLE artifacts ADD COLUMN engagement_id TEXT REFERENCES engagements(id) ON DELETE SET NULL;
ALTER TABLE artifacts ADD COLUMN run_id TEXT REFERENCES runs(id) ON DELETE SET NULL;
ALTER TABLE artifacts ADD COLUMN action_execution_id TEXT REFERENCES action_executions(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_artifacts_engagement_captured ON artifacts(engagement_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_artifacts_run_captured ON artifacts(run_id, captured_at DESC);
```

## Data Flow (v5)

1. Scheduler creates a `run`.
2. Proposer inserts actions into `action_queue`.
3. Worker leases queue items, executes tools, writes `action_executions`.
4. Tool outputs are stored in `artifacts` linked to `run` and execution.
5. Ingestion updates graph (`nodes`, `edges`) as before.
6. Finding materializer upserts `findings` and appends `finding_events`.
7. Risk aggregator writes `risk_snapshots`.

## Migration Strategy

1. Add tables and columns only (no destructive migration).
2. Create one default engagement and backfill (implemented in `src/db/migrations/v5.ts` Part D):
   - If existing `scans` rows exist, create a default engagement (`name='default'`, `status='active'`)
   - `scans.engagement_id`: backfill with default engagement ID where NULL
   - `artifacts.engagement_id`: backfill with default engagement ID where NULL
   - Fresh DBs (no existing scans) skip backfill entirely
3. Keep all existing APIs working; v5 features are opt-in.
4. Tests (`tests/db/migrations/v5.test.ts`):
   - Schema creation and indexes (7 tables, 15 indexes)
   - Queue dedupe partial unique index behavior (queued + running states)
   - FK cascade delete (multi-level: engagement → runs/action_queue/findings → children)
   - FK ON DELETE SET NULL behavior (run deletion → action_queue.run_id nullified)
   - Backfill: existing scans get default engagement, fresh DB skips backfill

## Out of Scope for v5

1. Multi-tenant partitioning of `nodes/edges`
2. Full policy engine implementation
3. Frontend/dashboard implementation

## v6 Candidate

To support multiple engagements in one DB, move from global node uniqueness to engagement-aware uniqueness:

1. add `engagement_id` to `nodes` and `edges`
2. make node unique key `(engagement_id, natural_key)`
3. scope repositories and queries by engagement
