import { describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';

describe('Migration v1', () => {
  it('creates the complete Assessment core schema without lifecycle concepts', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const tables = (
      db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{
        name: string;
      }>
    ).map((row) => row.name);
    expect(tables).toEqual(
      expect.arrayContaining([
        'assessments',
        'activities',
        'entities',
        'relations',
        'artifacts',
        'technique_docs',
      ]),
    );
    expect(tables).not.toEqual(
      expect.arrayContaining([
        'engagements',
        'missions',
        'actions',
        'attack_hypotheses',
        'hypothesis_events',
        'runs',
        'action_executions',
        'observations',
        'nodes',
        'edges',
      ]),
    );
    expect(db.pragma('user_version', { simple: true })).toBe(1);
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

  it('rejects a populated database from the removed migration history', () => {
    const db = new Database(':memory:');
    db.exec('CREATE TABLE missions (id TEXT PRIMARY KEY)');
    db.pragma('user_version = 13');
    expect(() => migrateDatabase(db)).toThrow(/recreate it with migration v1/);
    db.close();
  });
});
