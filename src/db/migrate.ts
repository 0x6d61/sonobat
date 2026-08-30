import type Database from 'better-sqlite3';
import {
  getSchemaVersion,
  runMigrations,
  LATEST_VERSION,
  setSchemaVersion,
} from './migrations/index.js';

/**
 * Migrate a database to the single current schema.
 *
 * New databases run migration v1.
 * Current-schema databases are left unchanged even when their historical version is higher.
 * Legacy databases fail explicitly because the historical migration chain was squashed.
 */
export function migrateDatabase(db: Database.Database): void {
  db.pragma('foreign_keys = ON');

  const currentVersion = getSchemaVersion(db);
  if (hasCurrentSchema(db)) {
    if (currentVersion < LATEST_VERSION) setSchemaVersion(db, LATEST_VERSION);
    return;
  }

  const tableCount = (
    db
      .prepare(
        "SELECT COUNT(*) AS cnt FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
      )
      .get() as { cnt: number }
  ).cnt;
  if (tableCount === 0) {
    runMigrations(db, -1);
    return;
  }

  throw new Error(
    `Unsupported legacy schema version ${currentVersion}. Back up the database and recreate it with migration v1.`,
  );
}

function hasCurrentSchema(db: Database.Database): boolean {
  const requiredTables = ['assessments', 'activities', 'entities', 'relations', 'artifacts'];
  const placeholders = requiredTables.map(() => '?').join(', ');
  const rows = db
    .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (${placeholders})`)
    .all(...requiredTables) as Array<{ name: string }>;
  if (rows.length !== requiredTables.length) return false;
  const activityColumns = db.prepare('PRAGMA table_info(activities)').all() as Array<{
    name: string;
  }>;
  return activityColumns.some((column) => column.name === 'command');
}
