import type Database from 'better-sqlite3';
import type { Migration } from './index.js';

const migration: Migration = {
  version: 9,
  description: 'Replace graph and execution model with Entity, Relation, Action, and evaluations',
  up(db: Database.Database): void {
    db.exec(`
      DROP TABLE IF EXISTS observation_findings;
      DROP TABLE IF EXISTS observation_edges;
      DROP TABLE IF EXISTS observation_nodes;
      DROP TABLE IF EXISTS observations;
      DROP TABLE IF EXISTS finding_events;
      DROP TABLE IF EXISTS findings;
      DROP TABLE IF EXISTS risk_snapshots;
      DROP TABLE IF EXISTS action_executions;
      DROP TABLE IF EXISTS edges;
      DROP TABLE IF EXISTS nodes;
      DROP TABLE IF EXISTS graph_edge_kinds;
      DROP TABLE IF EXISTS graph_node_kinds;
      DROP TABLE IF EXISTS artifacts;
      DROP TABLE IF EXISTS action_queue;
      DROP TABLE IF EXISTS missions;
      DROP TABLE IF EXISTS runs;

      CREATE TABLE entity_kinds (
        kind        TEXT PRIMARY KEY,
        description TEXT NOT NULL
      );
      INSERT INTO entity_kinds (kind, description) VALUES
        ('ip_address', 'IP address observed in the assessment'),
        ('host', 'Host identified in the assessment'),
        ('virtual_host', 'Virtual host name'),
        ('network_endpoint', 'Transport endpoint exposed by a host'),
        ('service', 'Service running on a network endpoint'),
        ('application', 'Application under assessment'),
        ('web_endpoint', 'HTTP method and path exposed by an application'),
        ('account', 'Principal or account'),
        ('credential', 'Credential including passwords, hashes, keys, and tokens'),
        ('vulnerability', 'Weakness identified on an Entity');

      CREATE TABLE relation_kinds (
        kind        TEXT PRIMARY KEY,
        description TEXT NOT NULL
      );
      INSERT INTO relation_kinds (kind, description) VALUES
        ('IDENTIFIES', 'Source identifies target'),
        ('EXPOSES', 'Source exposes target'),
        ('RUNS', 'Source runs target'),
        ('ROUTES_TO', 'Source routes to target'),
        ('AUTHENTICATES_TO', 'Credential authenticates to target'),
        ('AFFECTS', 'Source affects target'),
        ('RELATED_TO', 'Generic relation between Entities');

      CREATE TABLE entities (
        id          TEXT PRIMARY KEY,
        kind        TEXT NOT NULL,
        natural_key TEXT NOT NULL UNIQUE,
        props_json  TEXT NOT NULL DEFAULT '{}',
        artifact_id TEXT,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        FOREIGN KEY (kind) REFERENCES entity_kinds(kind)
      );
      CREATE INDEX idx_entities_kind ON entities(kind);

      CREATE TABLE relations (
        id               TEXT PRIMARY KEY,
        kind             TEXT NOT NULL,
        source_entity_id TEXT NOT NULL,
        target_entity_id TEXT NOT NULL,
        props_json       TEXT NOT NULL DEFAULT '{}',
        artifact_id      TEXT,
        created_at       TEXT NOT NULL,
        FOREIGN KEY (kind) REFERENCES relation_kinds(kind),
        FOREIGN KEY (source_entity_id) REFERENCES entities(id) ON DELETE CASCADE,
        FOREIGN KEY (target_entity_id) REFERENCES entities(id) ON DELETE CASCADE,
        UNIQUE(kind, source_entity_id, target_entity_id)
      );
      CREATE INDEX idx_relations_source ON relations(source_entity_id);
      CREATE INDEX idx_relations_target ON relations(target_entity_id);

      CREATE TABLE missions (
        id                      TEXT PRIMARY KEY,
        engagement_id           TEXT NOT NULL,
        objective               TEXT NOT NULL,
        targets_json            TEXT NOT NULL DEFAULT '[]',
        success_conditions_json TEXT NOT NULL DEFAULT '[]',
        stop_conditions_json    TEXT NOT NULL DEFAULT '[]',
        status                  TEXT NOT NULL DEFAULT 'active',
        created_at              TEXT NOT NULL,
        completed_at            TEXT,
        FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
      );
      CREATE INDEX idx_missions_engagement_status
        ON missions(engagement_id, status, created_at DESC);

      CREATE TABLE actions (
        id               TEXT PRIMARY KEY,
        engagement_id    TEXT NOT NULL,
        mission_id       TEXT,
        parent_action_id TEXT,
        kind             TEXT NOT NULL,
        priority         INTEGER NOT NULL DEFAULT 100,
        dedupe_key       TEXT NOT NULL,
        params_json      TEXT NOT NULL DEFAULT '{}',
        state            TEXT NOT NULL DEFAULT 'queued',
        attempt_count    INTEGER NOT NULL DEFAULT 0,
        max_attempts     INTEGER NOT NULL DEFAULT 3,
        available_at     TEXT NOT NULL,
        lease_owner      TEXT,
        lease_expires_at TEXT,
        last_error       TEXT,
        created_at       TEXT NOT NULL,
        updated_at       TEXT NOT NULL,
        FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
        FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE,
        FOREIGN KEY (parent_action_id) REFERENCES actions(id) ON DELETE SET NULL
      );
      CREATE INDEX idx_actions_poll
        ON actions(state, available_at, priority, created_at);
      CREATE UNIQUE INDEX uq_actions_active_dedupe
        ON actions(engagement_id, dedupe_key)
        WHERE state IN ('queued', 'running', 'proposed');

      CREATE TABLE artifacts (
        id        TEXT PRIMARY KEY,
        action_id TEXT NOT NULL,
        path      TEXT NOT NULL,
        FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE,
        UNIQUE(action_id, path)
      );
      CREATE INDEX idx_artifacts_action ON artifacts(action_id);

      CREATE TABLE attack_hypotheses (
        id                     TEXT PRIMARY KEY,
        engagement_id          TEXT NOT NULL,
        mission_id             TEXT,
        title                  TEXT NOT NULL,
        objective              TEXT NOT NULL,
        status                 TEXT NOT NULL DEFAULT 'proposed',
        preconditions_json     TEXT NOT NULL DEFAULT '[]',
        blockers_json          TEXT NOT NULL DEFAULT '[]',
        validation_result_json TEXT NOT NULL DEFAULT '{}',
        dismissal_reason       TEXT,
        artifact_id            TEXT,
        created_at             TEXT NOT NULL,
        updated_at             TEXT NOT NULL,
        FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
        FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE SET NULL,
        FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE SET NULL
      );
      CREATE INDEX idx_attack_hypotheses_engagement_status
        ON attack_hypotheses(engagement_id, status, updated_at DESC);

      CREATE TABLE hypothesis_events (
        id                     TEXT PRIMARY KEY,
        hypothesis_id          TEXT NOT NULL,
        status                 TEXT NOT NULL,
        validation_result_json TEXT NOT NULL DEFAULT '{}',
        reason                 TEXT,
        artifact_id            TEXT,
        created_at             TEXT NOT NULL,
        FOREIGN KEY (hypothesis_id) REFERENCES attack_hypotheses(id) ON DELETE CASCADE,
        FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE SET NULL
      );
      CREATE INDEX idx_hypothesis_events_hypothesis_created
        ON hypothesis_events(hypothesis_id, created_at DESC);
    `);
  },
};

export default migration;
