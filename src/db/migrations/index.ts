/**
 * sonobat — Database migration registry
 *
 * Manages versioned migrations using SQLite's PRAGMA user_version.
 * Each migration has a version number and an up() function.
 */

import type Database from 'better-sqlite3';
import v1 from './v1.js';

export interface Migration {
  version: number;
  description: string;
  up(db: Database.Database): void;
}

/** All migrations in order. Must be sorted by version ascending. */
const migrations: Migration[] = [v1];

/** The latest schema version (after all migrations applied). */
export const LATEST_VERSION: number =
  migrations.length > 0 ? migrations[migrations.length - 1].version : 0;

/**
 * Get the current schema version from the database.
 */
export function getSchemaVersion(db: Database.Database): number {
  const row = db.prepare('PRAGMA user_version').get() as {
    user_version: number;
  };
  return row.user_version;
}

/**
 * Set the schema version in the database.
 */
export function setSchemaVersion(db: Database.Database, version: number): void {
  db.pragma(`user_version = ${version}`);
}

/**
 * Run all pending migrations from currentVersion to LATEST_VERSION.
 * Each migration runs inside a transaction for safety.
 */
export function runMigrations(db: Database.Database, currentVersion: number): void {
  for (const migration of migrations) {
    if (migration.version > currentVersion) {
      const runMigration = db.transaction(() => {
        migration.up(db);
      });
      runMigration();
    }
  }
  setSchemaVersion(db, LATEST_VERSION);
}
