import type Database from 'better-sqlite3';
import { getSchemaVersion, runMigrations, LATEST_VERSION } from './migrations/index.js';

/**
 * Migrate the database to the latest schema version.
 *
 * - New database (user_version = 0, no tables): runs ALL migrations from v0.
 * - Existing database (user_version = 0, has tables): runs incremental migrations from v1.
 * - Partially migrated: runs remaining migrations.
 * - Already up-to-date (user_version = LATEST_VERSION): no-op.
 */
export function migrateDatabase(db: Database.Database): void {
  db.pragma('foreign_keys = ON');

  const currentVersion = getSchemaVersion(db);

  if (currentVersion >= LATEST_VERSION) {
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
      // Brand new database: run ALL migrations including v0 (base schema)
      runMigrations(db, -1);
      return;
    }

    // Existing v0 database: run incremental migrations from v1
    runMigrations(db, 0);
    return;
  }

  // Partially migrated: run remaining migrations
  runMigrations(db, currentVersion);
}
