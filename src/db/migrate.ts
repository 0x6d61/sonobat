import type Database from 'better-sqlite3';
import { SCHEMA_SQL } from './schema.js';

/**
 * Run schema SQL to create all tables.
 * Enables foreign key enforcement before executing the schema.
 */
export function migrateDatabase(db: Database.Database): void {
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA_SQL);
}
