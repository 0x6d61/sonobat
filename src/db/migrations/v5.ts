/**
 * Migration v5: file_mtime + 運用テーブル (Continuous STG Pentest)
 *
 * Part A: technique_docs
 * - Adds `file_mtime` TEXT column (NULL-able) for incremental indexing.
 * - Adds composite index on (source, file_path) for efficient mtime lookups.
 *
 * Part B: 7 新テーブル
 * - engagements, runs, action_queue, action_executions,
 *   findings, finding_events, risk_snapshots
 *
 * Part C: scans/artifacts ALTER TABLE（リネージカラム追加）
 * - scans に engagement_id, run_id を追加
 * - artifacts に engagement_id, run_id, action_execution_id を追加
 *
 * Part D: 既存データの backfill
 * - 既存 scans がある場合、デフォルト engagement を作成
 * - scans.engagement_id と artifacts.engagement_id をデフォルト engagement で埋める
 *
 * See docs/v5-db-design.md for full design rationale.
 */

import type Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';
import type { Migration } from './index.js';

const migration: Migration = {
  version: 5,
  description:
    'Add file_mtime, operational tables (engagements, runs, action_queue, etc.), and lineage columns',
  up(db: Database.Database): void {
    // -------------------------------------------------------
    // Part A: technique_docs — file_mtime + 複合インデックス
    // -------------------------------------------------------
    db.exec(`
      ALTER TABLE technique_docs ADD COLUMN file_mtime TEXT;

      CREATE INDEX IF NOT EXISTS idx_technique_docs_source_filepath
        ON technique_docs(source, file_path);
    `);

    // -------------------------------------------------------
    // Part B: 運用テーブル — Continuous STG Pentest
    // -------------------------------------------------------

    // 1) engagements
    db.exec(`
      CREATE TABLE IF NOT EXISTS engagements (
        id                 TEXT PRIMARY KEY,
        name               TEXT NOT NULL,
        environment        TEXT NOT NULL DEFAULT 'stg',
        scope_json         TEXT NOT NULL DEFAULT '{}',
        policy_json        TEXT NOT NULL DEFAULT '{}',
        schedule_cron      TEXT,
        status             TEXT NOT NULL DEFAULT 'active',
        created_at         TEXT NOT NULL,
        updated_at         TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_engagements_status ON engagements(status);
    `);

    // 2) runs
    db.exec(`
      CREATE TABLE IF NOT EXISTS runs (
        id                 TEXT PRIMARY KEY,
        engagement_id      TEXT NOT NULL,
        trigger_kind       TEXT NOT NULL,
        trigger_ref        TEXT,
        status             TEXT NOT NULL,
        started_at         TEXT,
        finished_at        TEXT,
        summary_json       TEXT NOT NULL DEFAULT '{}',
        created_at         TEXT NOT NULL,
        FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_runs_engagement_created ON runs(engagement_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
    `);

    // 3) action_queue
    db.exec(`
      CREATE TABLE IF NOT EXISTS action_queue (
        id                 TEXT PRIMARY KEY,
        engagement_id      TEXT NOT NULL,
        run_id             TEXT,
        parent_action_id   TEXT,
        kind               TEXT NOT NULL,
        priority           INTEGER NOT NULL DEFAULT 100,
        dedupe_key         TEXT NOT NULL,
        params_json        TEXT NOT NULL DEFAULT '{}',
        state              TEXT NOT NULL,
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
    `);

    // 4) action_executions
    db.exec(`
      CREATE TABLE IF NOT EXISTS action_executions (
        id                 TEXT PRIMARY KEY,
        action_id          TEXT NOT NULL,
        run_id             TEXT,
        executor           TEXT NOT NULL,
        command            TEXT,
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
    `);

    // 5) findings
    db.exec(`
      CREATE TABLE IF NOT EXISTS findings (
        id                 TEXT PRIMARY KEY,
        engagement_id      TEXT NOT NULL,
        canonical_key      TEXT NOT NULL,
        node_id            TEXT,
        title              TEXT NOT NULL,
        severity           TEXT NOT NULL,
        confidence         TEXT NOT NULL,
        state              TEXT NOT NULL,
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
    `);

    // 6) finding_events
    db.exec(`
      CREATE TABLE IF NOT EXISTS finding_events (
        id                 TEXT PRIMARY KEY,
        finding_id         TEXT NOT NULL,
        run_id             TEXT,
        event_type         TEXT NOT NULL,
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
    `);

    // 7) risk_snapshots
    db.exec(`
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
    `);

    // -------------------------------------------------------
    // Part C: 既存テーブルへのリネージカラム追加
    // -------------------------------------------------------

    // scans に engagement_id, run_id を追加
    // NOTE: SQLite の ALTER TABLE は REFERENCES 句を無視するが、設計意図として記載
    db.exec(`
      ALTER TABLE scans ADD COLUMN engagement_id TEXT; -- REFERENCES engagements(id) ON DELETE SET NULL
      ALTER TABLE scans ADD COLUMN run_id TEXT;        -- REFERENCES runs(id) ON DELETE SET NULL
      CREATE INDEX IF NOT EXISTS idx_scans_engagement_started ON scans(engagement_id, started_at DESC);
    `);

    // artifacts に engagement_id, run_id, action_execution_id を追加
    db.exec(`
      ALTER TABLE artifacts ADD COLUMN engagement_id TEXT;        -- REFERENCES engagements(id) ON DELETE SET NULL
      ALTER TABLE artifacts ADD COLUMN run_id TEXT;               -- REFERENCES runs(id) ON DELETE SET NULL
      ALTER TABLE artifacts ADD COLUMN action_execution_id TEXT;  -- REFERENCES action_executions(id) ON DELETE SET NULL
      CREATE INDEX IF NOT EXISTS idx_artifacts_engagement_captured ON artifacts(engagement_id, captured_at DESC);
      CREATE INDEX IF NOT EXISTS idx_artifacts_run_captured ON artifacts(run_id, captured_at DESC);
    `);

    // -------------------------------------------------------
    // Part D: 既存データの backfill
    // -------------------------------------------------------
    const scanCount = (
      db.prepare('SELECT COUNT(*) AS cnt FROM scans').get() as { cnt: number }
    ).cnt;

    if (scanCount > 0) {
      const now = new Date().toISOString();
      const defaultEngId = randomUUID();

      // デフォルト engagement を作成
      db.prepare(
        `INSERT INTO engagements (id, name, environment, scope_json, policy_json, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(defaultEngId, 'default', 'stg', '{}', '{}', 'active', now, now);

      // scans.engagement_id をデフォルト engagement で埋める
      db.prepare('UPDATE scans SET engagement_id = ? WHERE engagement_id IS NULL').run(
        defaultEngId,
      );

      // artifacts.engagement_id をデフォルト engagement で埋める
      db.prepare('UPDATE artifacts SET engagement_id = ? WHERE engagement_id IS NULL').run(
        defaultEngId,
      );
    }
  },
};

export default migration;
