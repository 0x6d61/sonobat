/**
 * Migration v1: Add datalog_rules table
 *
 * This migration adds the datalog_rules table for storing
 * custom Datalog rules created by humans or AI agents.
 */

import type Database from 'better-sqlite3';
import type { Migration } from './index.js';

const migration: Migration = {
  version: 1,
  description: 'Add datalog_rules table',
  up(db: Database.Database): void {
    db.exec(`
      CREATE TABLE IF NOT EXISTS datalog_rules (
        id            TEXT PRIMARY KEY,
        name          TEXT NOT NULL UNIQUE,
        description   TEXT,
        rule_text     TEXT NOT NULL,
        generated_by  TEXT NOT NULL,            -- "human" | "ai" | "preset"
        is_preset     INTEGER NOT NULL DEFAULT 0,
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_datalog_rules_name ON datalog_rules(name);
    `);
  },
};

export default migration;
