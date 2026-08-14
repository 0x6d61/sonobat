import { describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';

describe('Migration v9', () => {
  it('creates the new domain schema and removes legacy concepts', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const tables = (
      db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{
        name: string;
      }>
    ).map((row) => row.name);
    expect(tables).toEqual(
      expect.arrayContaining([
        'engagements',
        'missions',
        'actions',
        'entities',
        'relations',
        'artifacts',
        'attack_hypotheses',
        'hypothesis_events',
      ]),
    );
    expect(tables).not.toEqual(
      expect.arrayContaining(['runs', 'action_executions', 'observations', 'nodes', 'edges']),
    );
    expect(db.pragma('user_version', { simple: true })).toBe(9);
    db.close();
  });

  it('defines Entity and Relation kinds in the migration', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    expect(db.prepare("SELECT kind FROM entity_kinds WHERE kind = 'credential'").get()).toEqual({
      kind: 'credential',
    });
    expect(
      db.prepare("SELECT kind FROM relation_kinds WHERE kind = 'AUTHENTICATES_TO'").get(),
    ).toEqual({ kind: 'AUTHENTICATES_TO' });
    db.close();
  });
});
