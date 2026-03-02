/**
 * Migration v5: Add file_mtime column and composite index to technique_docs
 *
 * - Adds `file_mtime` TEXT column (NULL-able) for incremental indexing.
 * - Adds composite index on (source, file_path) for efficient mtime lookups.
 * - No impact on FTS5 triggers (they only reference title, category, content).
 */

import type Database from 'better-sqlite3';
import type { Migration } from './index.js';

const migration: Migration = {
  version: 5,
  description: 'Add file_mtime column and source+file_path index to technique_docs',
  up(db: Database.Database): void {
    db.exec(`
      ALTER TABLE technique_docs ADD COLUMN file_mtime TEXT;

      CREATE INDEX IF NOT EXISTS idx_technique_docs_source_filepath
        ON technique_docs(source, file_path);
    `);
  },
};

export default migration;
