import type Database from 'better-sqlite3';
import type { Migration } from './index.js';

const migration: Migration = {
  version: 7,
  description: 'Add Artifact Tree lineage and metadata columns',
  up(db: Database.Database): void {
    db.exec(`
      ALTER TABLE artifacts ADD COLUMN mission_id TEXT REFERENCES missions(id) ON DELETE SET NULL;
      ALTER TABLE artifacts ADD COLUMN action_id TEXT REFERENCES action_queue(id) ON DELETE SET NULL;
      ALTER TABLE artifacts ADD COLUMN media_type TEXT;
      ALTER TABLE artifacts ADD COLUMN sensitivity TEXT NOT NULL DEFAULT 'internal';

      CREATE INDEX idx_artifacts_mission_captured
        ON artifacts(mission_id, captured_at DESC);
      CREATE INDEX idx_artifacts_action_captured
        ON artifacts(action_id, captured_at DESC);
      CREATE INDEX idx_artifacts_execution_captured
        ON artifacts(action_execution_id, captured_at DESC);
    `);
  },
};

export default migration;
