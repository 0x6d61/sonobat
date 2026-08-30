import type Database from 'better-sqlite3';
import v1 from './v1.js';

export interface Migration {
  version: number;
  description: string;
  up(db: Database.Database): void;
}

const migrations: Migration[] = [v1];

export const LATEST_VERSION: number = migrations[migrations.length - 1].version;

export function getSchemaVersion(db: Database.Database): number {
  const row = db.prepare('PRAGMA user_version').get() as { user_version: number };
  return row.user_version;
}

export function setSchemaVersion(db: Database.Database, version: number): void {
  db.pragma(`user_version = ${version}`);
}

export function runMigrations(db: Database.Database, currentVersion: number): void {
  for (const migration of migrations) {
    if (migration.version > currentVersion) {
      const runMigration = db.transaction(() => {
        migration.up(db);
      });
      runMigration();
      setSchemaVersion(db, migration.version);
    }
  }
}
