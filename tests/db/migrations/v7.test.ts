import { describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';

describe('Migration v7', () => {
  it('Artifact Treeの由来とメタデータ列を追加する', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const columns = db.prepare("PRAGMA table_info('artifacts')").all() as Array<{ name: string }>;
    const names = columns.map((column) => column.name);
    expect(names).toContain('mission_id');
    expect(names).toContain('action_id');
    expect(names).toContain('action_execution_id');
    expect(names).toContain('media_type');
    expect(names).toContain('sensitivity');
  });
});
