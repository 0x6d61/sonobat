import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';

describe('Migration v5: file_mtime + 複合インデックス', () => {
  let db: InstanceType<typeof Database>;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
  });

  it('technique_docs テーブルに file_mtime カラムが存在する', () => {
    const columns = db
      .prepare("PRAGMA table_info('technique_docs')")
      .all() as Array<{ name: string; type: string; notnull: number }>;

    const fileMtimeCol = columns.find((c) => c.name === 'file_mtime');
    expect(fileMtimeCol).toBeDefined();
    expect(fileMtimeCol!.type).toBe('TEXT');
    expect(fileMtimeCol!.notnull).toBe(0); // NULL 許容
  });

  it('idx_technique_docs_source_filepath インデックスが存在する', () => {
    const indexes = db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='technique_docs' AND name='idx_technique_docs_source_filepath'",
      )
      .all() as Array<{ name: string }>;

    expect(indexes).toHaveLength(1);
  });

  it('既存データの file_mtime は NULL になる', () => {
    // Insert a doc without file_mtime (existing behavior)
    db.prepare(
      `INSERT INTO technique_docs (id, source, file_path, title, category, content, chunk_index, indexed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('test-id', 'hacktricks', 'test.md', 'Test', 'test', 'content', 0, '2024-01-01T00:00:00Z');

    const row = db.prepare('SELECT file_mtime FROM technique_docs WHERE id = ?').get('test-id') as {
      file_mtime: string | null;
    };
    expect(row.file_mtime).toBeNull();
  });

  it('file_mtime に値を設定してインサートできる', () => {
    db.prepare(
      `INSERT INTO technique_docs (id, source, file_path, title, category, content, chunk_index, indexed_at, file_mtime)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      'test-id-2',
      'hacktricks',
      'test.md',
      'Test',
      'test',
      'content',
      0,
      '2024-01-01T00:00:00Z',
      '2024-06-15T12:00:00.000Z',
    );

    const row = db
      .prepare('SELECT file_mtime FROM technique_docs WHERE id = ?')
      .get('test-id-2') as { file_mtime: string | null };
    expect(row.file_mtime).toBe('2024-06-15T12:00:00.000Z');
  });

  it('スキーマバージョンが 5 になっている', () => {
    const row = db.prepare('PRAGMA user_version').get() as { user_version: number };
    expect(row.user_version).toBe(5);
  });
});
