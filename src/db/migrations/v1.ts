import type Database from 'better-sqlite3';
import type { Migration } from './index.js';

const migration: Migration = {
  version: 1,
  description: 'Create the complete Assessment core schema',
  up(db: Database.Database): void {
    db.exec(`
      CREATE TABLE assessments (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE entity_kinds (
        kind        TEXT PRIMARY KEY,
        description TEXT NOT NULL
      );
      INSERT INTO entity_kinds (kind, description) VALUES
        ('ip_address', 'Confirmed IP address'),
        ('host', 'Host identified by address or name'),
        ('virtual_host', 'Name-based virtual host or HTTP Host authority'),
        ('network_endpoint', 'Transport endpoint exposed by a host'),
        ('service', 'Service running on a network endpoint'),
        ('application', 'Identified web or other application'),
        ('web_endpoint', 'HTTP method and path exposed by an application'),
        ('account', 'Identified user or service account'),
        ('credential', 'Credential associated with an account or service'),
        ('vulnerability', 'Confirmed weakness');

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

      CREATE TABLE activities (
        id             TEXT PRIMARY KEY,
        assessment_id  TEXT NOT NULL,
        kind           TEXT NOT NULL,
        command        TEXT,
        description    TEXT NOT NULL,
        target         TEXT,
        status         TEXT NOT NULL CHECK (status IN ('started', 'completed', 'failed')),
        started_at     TEXT NOT NULL,
        finished_at    TEXT,
        result_summary TEXT,
        error_summary  TEXT,
        created_at     TEXT NOT NULL,
        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
      );
      CREATE INDEX idx_activities_assessment_started
        ON activities(assessment_id, started_at, created_at);

      CREATE TABLE artifacts (
        id            TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL,
        activity_id   TEXT,
        path          TEXT NOT NULL,
        media_type    TEXT,
        sha256        TEXT,
        captured_at   TEXT NOT NULL,
        created_at    TEXT NOT NULL,
        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE,
        FOREIGN KEY (activity_id) REFERENCES activities(id) ON DELETE SET NULL
      );
      CREATE INDEX idx_artifacts_assessment_captured
        ON artifacts(assessment_id, captured_at, created_at);
      CREATE INDEX idx_artifacts_activity
        ON artifacts(activity_id, captured_at, created_at);

      CREATE TABLE entities (
        id            TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL,
        kind          TEXT NOT NULL,
        natural_key   TEXT NOT NULL,
        props_json    TEXT NOT NULL DEFAULT '{}',
        artifact_id   TEXT,
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL,
        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE,
        FOREIGN KEY (kind) REFERENCES entity_kinds(kind),
        UNIQUE (assessment_id, natural_key),
        UNIQUE (assessment_id, id)
      );
      CREATE INDEX idx_entities_assessment_kind
        ON entities(assessment_id, kind, created_at);

      CREATE TABLE relations (
        id               TEXT PRIMARY KEY,
        assessment_id    TEXT NOT NULL,
        kind             TEXT NOT NULL,
        source_entity_id TEXT NOT NULL,
        target_entity_id TEXT NOT NULL,
        props_json       TEXT NOT NULL DEFAULT '{}',
        artifact_id      TEXT,
        created_at       TEXT NOT NULL,
        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE,
        FOREIGN KEY (kind) REFERENCES relation_kinds(kind),
        FOREIGN KEY (assessment_id, source_entity_id)
          REFERENCES entities(assessment_id, id) ON DELETE CASCADE,
        FOREIGN KEY (assessment_id, target_entity_id)
          REFERENCES entities(assessment_id, id) ON DELETE CASCADE,
        UNIQUE (assessment_id, kind, source_entity_id, target_entity_id)
      );
      CREATE INDEX idx_relations_assessment_source
        ON relations(assessment_id, source_entity_id, created_at);
      CREATE INDEX idx_relations_assessment_target
        ON relations(assessment_id, target_entity_id, created_at);

      CREATE TABLE technique_docs (
        id          TEXT PRIMARY KEY,
        source      TEXT NOT NULL,
        file_path   TEXT NOT NULL,
        title       TEXT NOT NULL,
        category    TEXT NOT NULL,
        content     TEXT NOT NULL,
        chunk_index INTEGER NOT NULL,
        indexed_at  TEXT NOT NULL,
        file_mtime  TEXT
      );
      CREATE INDEX idx_technique_docs_source_filepath
        ON technique_docs(source, file_path);

      CREATE VIRTUAL TABLE technique_docs_fts USING fts5(
        title, category, content,
        content=technique_docs,
        content_rowid=rowid,
        tokenize='porter unicode61'
      );

      CREATE TRIGGER technique_docs_ai AFTER INSERT ON technique_docs BEGIN
        INSERT INTO technique_docs_fts(rowid, title, category, content)
        VALUES (new.rowid, new.title, new.category, new.content);
      END;

      CREATE TRIGGER technique_docs_ad AFTER DELETE ON technique_docs BEGIN
        INSERT INTO technique_docs_fts(technique_docs_fts, rowid, title, category, content)
        VALUES ('delete', old.rowid, old.title, old.category, old.content);
      END;

      CREATE TRIGGER technique_docs_au AFTER UPDATE ON technique_docs BEGIN
        INSERT INTO technique_docs_fts(technique_docs_fts, rowid, title, category, content)
        VALUES ('delete', old.rowid, old.title, old.category, old.content);
        INSERT INTO technique_docs_fts(rowid, title, category, content)
        VALUES (new.rowid, new.title, new.category, new.content);
      END;
    `);
  },
};

export default migration;
