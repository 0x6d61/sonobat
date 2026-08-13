import { describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';

describe('Migration v6', () => {
  it('Mission、Observation、由来テーブルを作成する', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all() as Array<{ name: string }>;
    const names = tables.map((row) => row.name);
    expect(names).toContain('missions');
    expect(names).toContain('observations');
    expect(names).toContain('observation_nodes');
    expect(names).toContain('observation_edges');
    expect(names).toContain('observation_findings');
  });

  it('Credentialを含むNode型とEdge型をMigrationで登録する', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    expect(db.prepare("SELECT kind FROM graph_node_kinds WHERE kind = 'credential'").get()).toEqual(
      {
        kind: 'credential',
      },
    );
    expect(
      db.prepare("SELECT kind FROM graph_edge_kinds WHERE kind = 'SERVICE_CREDENTIAL'").get(),
    ).toEqual({ kind: 'SERVICE_CREDENTIAL' });
  });
});
