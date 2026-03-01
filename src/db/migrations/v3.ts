/**
 * Migration v3: Add technique_docs table with FTS5 full-text search
 *
 * Creates a technique documentation table for indexing penetration testing
 * knowledge (e.g. HackTricks) and a FTS5 virtual table for efficient search.
 */

import type Database from 'better-sqlite3';
import type { Migration } from './index.js';

const migration: Migration = {
  version: 3,
  description: 'Add technique_docs table with FTS5 full-text search',
  up(db: Database.Database): void {
    db.exec(`
      CREATE TABLE IF NOT EXISTS technique_docs (
        id            TEXT PRIMARY KEY,
        source        TEXT NOT NULL,
        file_path     TEXT NOT NULL,
        title         TEXT NOT NULL,
        category      TEXT NOT NULL,
        content       TEXT NOT NULL,
        chunk_index   INTEGER NOT NULL,
        indexed_at    TEXT NOT NULL
      );

      CREATE VIRTUAL TABLE IF NOT EXISTS technique_docs_fts USING fts5(
        title, category, content,
        content=technique_docs,
        content_rowid=rowid,
        tokenize='porter unicode61'
      );

      CREATE TRIGGER IF NOT EXISTS technique_docs_ai AFTER INSERT ON technique_docs BEGIN
        INSERT INTO technique_docs_fts(rowid, title, category, content)
        VALUES (new.rowid, new.title, new.category, new.content);
      END;

      CREATE TRIGGER IF NOT EXISTS technique_docs_ad AFTER DELETE ON technique_docs BEGIN
        INSERT INTO technique_docs_fts(technique_docs_fts, rowid, title, category, content)
        VALUES ('delete', old.rowid, old.title, old.category, old.content);
      END;

      CREATE TRIGGER IF NOT EXISTS technique_docs_au AFTER UPDATE ON technique_docs BEGIN
        INSERT INTO technique_docs_fts(technique_docs_fts, rowid, title, category, content)
        VALUES ('delete', old.rowid, old.title, old.category, old.content);
        INSERT INTO technique_docs_fts(rowid, title, category, content)
        VALUES (new.rowid, new.title, new.category, new.content);
      END;
    `);
  },
};

export default migration;
