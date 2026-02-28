import type Database from 'better-sqlite3';
import { SCHEMA_SQL } from './schema.js';
import {
  getSchemaVersion,
  setSchemaVersion,
  runMigrations,
  LATEST_VERSION,
} from './migrations/index.js';

/**
 * Migrate the database to the latest schema version.
 *
 * - New database (user_version = 0, no tables): runs full schema SQL and sets version.
 * - Existing database (user_version = 0, has tables): runs incremental migrations.
 * - Already up-to-date (user_version = LATEST_VERSION): no-op.
 */
export function migrateDatabase(db: Database.Database): void {
  db.pragma('foreign_keys = ON');

  const currentVersion = getSchemaVersion(db);

  if (currentVersion >= LATEST_VERSION) {
    // Already up to date — but still run schema SQL for IF NOT EXISTS safety
    db.exec(SCHEMA_SQL);
    return;
  }

  if (currentVersion === 0) {
    // Check if this is a truly new DB or an existing v0 DB
    const tableCount = (
      db
        .prepare(
          "SELECT COUNT(*) AS cnt FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        )
        .get() as { cnt: number }
    ).cnt;

    if (tableCount === 0) {
      // Brand new database: run full schema and set version
      db.exec(SCHEMA_SQL);
      setSchemaVersion(db, LATEST_VERSION);
      return;
    }

    // Existing v0 database: run incremental migrations
    runMigrations(db, currentVersion);
    return;
  }

  // Partially migrated: run remaining migrations
  runMigrations(db, currentVersion);
}
