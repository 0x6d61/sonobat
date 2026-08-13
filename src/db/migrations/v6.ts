import type Database from 'better-sqlite3';
import type { Migration } from './index.js';

const migration: Migration = {
  version: 6,
  description: 'Add missions, action mission membership, and observation provenance',
  up(db: Database.Database): void {
    db.exec(`
      CREATE TABLE graph_node_kinds (
        kind                TEXT PRIMARY KEY,
        description         TEXT NOT NULL
      );

      CREATE TABLE graph_edge_kinds (
        kind                TEXT PRIMARY KEY,
        description         TEXT NOT NULL
      );

      INSERT INTO graph_node_kinds (kind, description) VALUES
        ('host', 'Network host or domain'),
        ('vhost', 'Virtual host'),
        ('service', 'Network endpoint and application protocol'),
        ('endpoint', 'Application endpoint'),
        ('input', 'Application input'),
        ('observation', 'Legacy graph observation node'),
        ('credential', 'Credential discovered during an assessment'),
        ('vulnerability', 'Discovered vulnerability'),
        ('cve', 'CVE reference'),
        ('svc_observation', 'Legacy service observation node');

      INSERT INTO graph_edge_kinds (kind, description) VALUES
        ('HOST_SERVICE', 'Host exposes service'),
        ('HOST_VHOST', 'Host serves virtual host'),
        ('SERVICE_ENDPOINT', 'Service exposes endpoint'),
        ('SERVICE_INPUT', 'Service accepts input'),
        ('SERVICE_CREDENTIAL', 'Credential is valid for service'),
        ('SERVICE_VULNERABILITY', 'Service has vulnerability'),
        ('SERVICE_OBSERVATION', 'Observation describes service'),
        ('ENDPOINT_INPUT', 'Endpoint accepts input'),
        ('ENDPOINT_VULNERABILITY', 'Endpoint has vulnerability'),
        ('ENDPOINT_CREDENTIAL', 'Credential is valid for endpoint'),
        ('INPUT_OBSERVATION', 'Observation describes input'),
        ('VULNERABILITY_CVE', 'Vulnerability references CVE'),
        ('VHOST_ENDPOINT', 'Virtual host exposes endpoint');

      CREATE TABLE missions (
        id                  TEXT PRIMARY KEY,
        engagement_id       TEXT NOT NULL,
        run_id              TEXT,
        objective           TEXT NOT NULL,
        targets_json        TEXT NOT NULL DEFAULT '[]',
        success_conditions_json TEXT NOT NULL DEFAULT '[]',
        stop_conditions_json TEXT NOT NULL DEFAULT '[]',
        status              TEXT NOT NULL DEFAULT 'active',
        created_at          TEXT NOT NULL,
        completed_at        TEXT,
        FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
        FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE SET NULL
      );
      CREATE INDEX idx_missions_engagement_status
        ON missions(engagement_id, status, created_at DESC);

      ALTER TABLE action_queue ADD COLUMN mission_id TEXT REFERENCES missions(id) ON DELETE CASCADE;
      CREATE INDEX idx_action_queue_mission_created
        ON action_queue(mission_id, created_at);

      CREATE TABLE observations (
        id                  TEXT PRIMARY KEY,
        artifact_id         TEXT NOT NULL,
        actor               TEXT NOT NULL,
        dedupe_key          TEXT NOT NULL UNIQUE,
        content_json        TEXT NOT NULL,
        confidence          REAL,
        created_at          TEXT NOT NULL,
        FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
      );
      CREATE INDEX idx_observations_artifact ON observations(artifact_id, created_at);

      CREATE TABLE observation_nodes (
        observation_id      TEXT NOT NULL,
        node_id             TEXT NOT NULL,
        PRIMARY KEY (observation_id, node_id),
        FOREIGN KEY (observation_id) REFERENCES observations(id) ON DELETE CASCADE,
        FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
      );

      CREATE TABLE observation_edges (
        observation_id      TEXT NOT NULL,
        edge_id             TEXT NOT NULL,
        PRIMARY KEY (observation_id, edge_id),
        FOREIGN KEY (observation_id) REFERENCES observations(id) ON DELETE CASCADE,
        FOREIGN KEY (edge_id) REFERENCES edges(id) ON DELETE CASCADE
      );

      CREATE TABLE observation_findings (
        observation_id      TEXT NOT NULL,
        finding_id          TEXT NOT NULL,
        PRIMARY KEY (observation_id, finding_id),
        FOREIGN KEY (observation_id) REFERENCES observations(id) ON DELETE CASCADE,
        FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
      );
    `);
  },
};

export default migration;
