/**
 * Migration v2: Add status column to vulnerabilities table
 *
 * Adds a `status` column to track the verification state of vulnerabilities.
 * Values: 'unverified' (default), 'confirmed', 'false_positive', 'not_exploitable'
 */

import type Database from 'better-sqlite3';
import type { Migration } from './index.js';

const migration: Migration = {
  version: 2,
  description: 'Add status column to vulnerabilities table',
  up(db: Database.Database): void {
    db.exec(`
      ALTER TABLE vulnerabilities ADD COLUMN status TEXT NOT NULL DEFAULT 'unverified';
    `);
  },
};

export default migration;
