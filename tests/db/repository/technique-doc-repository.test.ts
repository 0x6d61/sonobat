import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { TechniqueDocRepository } from '../../../src/db/repository/technique-doc-repository.js';
import type { CreateTechniqueDocInput } from '../../../src/db/repository/technique-doc-repository.js';

describe('TechniqueDocRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: TechniqueDocRepository;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    repo = new TechniqueDocRepository(db);
  });

  function makeDoc(overrides: Partial<CreateTechniqueDocInput> = {}): CreateTechniqueDocInput {
    return {
      source: 'hacktricks',
      filePath: 'linux-hardening/privilege-escalation/docker-breakout.md',
      title: 'Docker Breakout',
      category: 'linux-hardening/privilege-escalation',
      content: 'Docker breakout techniques for privilege escalation in containerized environments.',
      chunkIndex: 0,
      ...overrides,
    };
  }

  // =========================================================
  // index (バルクインサート)
  // =========================================================

  it('index — 複数ドキュメントをバルクインサートできる', () => {
    const docs = [
      makeDoc({ title: 'Docker Breakout', chunkIndex: 0 }),
      makeDoc({
        title: 'Docker Breakout',
        chunkIndex: 1,
        content: 'Using nsenter to escape containers.',
      }),
      makeDoc({
        filePath: 'windows-hardening/active-directory.md',
        title: 'Active Directory',
        category: 'windows-hardening',
        content: 'Active Directory enumeration and exploitation techniques.',
        chunkIndex: 0,
      }),
    ];

    const count = repo.index(docs);
    expect(count).toBe(3);
    expect(repo.count()).toBe(3);
  });

  it('index — 空配列では 0 を返す', () => {
    const count = repo.index([]);
    expect(count).toBe(0);
  });

  // =========================================================
  // search (FTS5 MATCH + BM25)
  // =========================================================

  it('search — FTS5 で全文検索できる', () => {
    repo.index([
      makeDoc({ content: 'Docker breakout techniques for privilege escalation.' }),
      makeDoc({
        filePath: 'web/sql-injection.md',
        title: 'SQL Injection',
        category: 'web',
        content: 'SQL injection attack vectors and payloads.',
        chunkIndex: 0,
      }),
    ]);

    const results = repo.search('docker breakout');
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].title).toBe('Docker Breakout');
    expect(results[0].score).toBeGreaterThan(0);
  });

  it('search — マッチしない場合は空配列', () => {
    repo.index([makeDoc()]);
    const results = repo.search('nonexistent_xyz_query');
    expect(results).toHaveLength(0);
  });

  it('search — limit で結果数を制限できる', () => {
    repo.index([
      makeDoc({ chunkIndex: 0, content: 'Docker container escape method one.' }),
      makeDoc({ chunkIndex: 1, content: 'Docker container escape method two.' }),
      makeDoc({ chunkIndex: 2, content: 'Docker container escape method three.' }),
    ]);

    const results = repo.search('docker container escape', { limit: 2 });
    expect(results).toHaveLength(2);
  });

  // =========================================================
  // search with category filter
  // =========================================================

  it('search — category フィルタで絞り込める', () => {
    repo.index([
      makeDoc({
        category: 'linux-hardening',
        content: 'Linux privilege escalation via SUID binaries.',
      }),
      makeDoc({
        filePath: 'windows-hardening/priv-esc.md',
        title: 'Windows Priv Esc',
        category: 'windows-hardening',
        content: 'Windows privilege escalation via token impersonation.',
        chunkIndex: 0,
      }),
    ]);

    const results = repo.search('privilege escalation', { category: 'windows-hardening' });
    expect(results).toHaveLength(1);
    expect(results[0].category).toBe('windows-hardening');
  });

  // =========================================================
  // listCategories
  // =========================================================

  it('listCategories — ユニークなカテゴリ一覧を返す', () => {
    repo.index([
      makeDoc({ category: 'linux-hardening/privilege-escalation' }),
      makeDoc({
        filePath: 'web/sqli.md',
        title: 'SQLi',
        category: 'web',
        chunkIndex: 0,
      }),
      makeDoc({
        filePath: 'web/xss.md',
        title: 'XSS',
        category: 'web',
        chunkIndex: 0,
      }),
    ]);

    const categories = repo.listCategories();
    expect(categories).toHaveLength(2);
    expect(categories).toContain('linux-hardening/privilege-escalation');
    expect(categories).toContain('web');
  });

  it('listCategories — 空の場合は空配列', () => {
    const categories = repo.listCategories();
    expect(categories).toHaveLength(0);
  });

  // =========================================================
  // findByCategory
  // =========================================================

  it('findByCategory — カテゴリでドキュメントを取得できる', () => {
    repo.index([
      makeDoc({ category: 'web', filePath: 'web/sqli.md', title: 'SQLi', chunkIndex: 0 }),
      makeDoc({ category: 'web', filePath: 'web/xss.md', title: 'XSS', chunkIndex: 0 }),
      makeDoc({ category: 'linux-hardening', chunkIndex: 0 }),
    ]);

    const docs = repo.findByCategory('web');
    expect(docs).toHaveLength(2);
    expect(docs.every((d) => d.category === 'web')).toBe(true);
  });

  it('findByCategory — fileMtime が正しく返される', () => {
    repo.index([
      makeDoc({
        category: 'web',
        filePath: 'web/sqli.md',
        title: 'SQLi',
        chunkIndex: 0,
        fileMtime: '2024-06-15T12:00:00.000Z',
      }),
    ]);

    const docs = repo.findByCategory('web');
    expect(docs).toHaveLength(1);
    expect(docs[0].fileMtime).toBe('2024-06-15T12:00:00.000Z');
  });

  // =========================================================
  // deleteBySource
  // =========================================================

  it('deleteBySource — ソースで一括削除できる', () => {
    repo.index([
      makeDoc({ source: 'hacktricks' }),
      makeDoc({
        source: 'custom',
        filePath: 'custom/notes.md',
        title: 'Custom Notes',
        category: 'custom',
        chunkIndex: 0,
      }),
    ]);

    expect(repo.count()).toBe(2);

    const deleted = repo.deleteBySource('hacktricks');
    expect(deleted).toBe(1);
    expect(repo.count()).toBe(1);
  });

  // =========================================================
  // count
  // =========================================================

  it('count — 総ドキュメント数を返す', () => {
    expect(repo.count()).toBe(0);

    repo.index([makeDoc(), makeDoc({ chunkIndex: 1, content: 'Second chunk.' })]);
    expect(repo.count()).toBe(2);
  });

  // =========================================================
  // index with fileMtime
  // =========================================================

  it('index — fileMtime 付きでインサートできる', () => {
    const docs = [
      makeDoc({ fileMtime: '2024-06-15T12:00:00.000Z' }),
      makeDoc({ chunkIndex: 1, content: 'chunk 2', fileMtime: '2024-06-15T12:00:00.000Z' }),
    ];

    const count = repo.index(docs);
    expect(count).toBe(2);

    const row = db
      .prepare('SELECT file_mtime FROM technique_docs LIMIT 1')
      .get() as { file_mtime: string | null };
    expect(row.file_mtime).toBe('2024-06-15T12:00:00.000Z');
  });

  it('index — fileMtime 省略時は NULL になる', () => {
    repo.index([makeDoc()]);

    const row = db
      .prepare('SELECT file_mtime FROM technique_docs LIMIT 1')
      .get() as { file_mtime: string | null };
    expect(row.file_mtime).toBeNull();
  });

  // =========================================================
  // findMtimesBySource
  // =========================================================

  it('findMtimesBySource — ソースごとの file_path → file_mtime マップを返す', () => {
    repo.index([
      makeDoc({
        filePath: 'web/sqli.md',
        chunkIndex: 0,
        fileMtime: '2024-01-01T00:00:00.000Z',
      }),
      makeDoc({
        filePath: 'web/sqli.md',
        chunkIndex: 1,
        fileMtime: '2024-01-01T00:00:00.000Z',
      }),
      makeDoc({
        filePath: 'web/xss.md',
        chunkIndex: 0,
        fileMtime: '2024-06-01T00:00:00.000Z',
      }),
    ]);

    const mtimes = repo.findMtimesBySource('hacktricks');
    expect(mtimes.size).toBe(2);
    expect(mtimes.get('web/sqli.md')).toBe('2024-01-01T00:00:00.000Z');
    expect(mtimes.get('web/xss.md')).toBe('2024-06-01T00:00:00.000Z');
  });

  it('findMtimesBySource — 空の場合は空マップを返す', () => {
    const mtimes = repo.findMtimesBySource('hacktricks');
    expect(mtimes.size).toBe(0);
  });

  it('findMtimesBySource — 別ソースのデータは含まない', () => {
    repo.index([
      makeDoc({ source: 'hacktricks', filePath: 'a.md', fileMtime: '2024-01-01T00:00:00.000Z' }),
      makeDoc({
        source: 'custom',
        filePath: 'b.md',
        category: 'custom',
        fileMtime: '2024-02-01T00:00:00.000Z',
      }),
    ]);

    const mtimes = repo.findMtimesBySource('hacktricks');
    expect(mtimes.size).toBe(1);
    expect(mtimes.has('a.md')).toBe(true);
    expect(mtimes.has('b.md')).toBe(false);
  });

  // =========================================================
  // deleteBySourceAndFilePaths
  // =========================================================

  it('deleteBySourceAndFilePaths — 指定ファイルパスのドキュメントを削除する', () => {
    repo.index([
      makeDoc({ filePath: 'web/sqli.md', chunkIndex: 0 }),
      makeDoc({ filePath: 'web/sqli.md', chunkIndex: 1, content: 'chunk 2' }),
      makeDoc({ filePath: 'web/xss.md', chunkIndex: 0 }),
      makeDoc({ filePath: 'linux/docker.md', category: 'linux', chunkIndex: 0 }),
    ]);

    expect(repo.count()).toBe(4);

    const deleted = repo.deleteBySourceAndFilePaths('hacktricks', ['web/sqli.md', 'web/xss.md']);
    expect(deleted).toBe(3); // sqli: 2 chunks + xss: 1 chunk
    expect(repo.count()).toBe(1);
  });

  it('deleteBySourceAndFilePaths — 空配列では 0 を返す', () => {
    repo.index([makeDoc()]);
    const deleted = repo.deleteBySourceAndFilePaths('hacktricks', []);
    expect(deleted).toBe(0);
    expect(repo.count()).toBe(1);
  });

  it('deleteBySourceAndFilePaths — 別ソースのドキュメントは削除しない', () => {
    repo.index([
      makeDoc({ source: 'hacktricks', filePath: 'web/sqli.md' }),
      makeDoc({ source: 'custom', filePath: 'web/sqli.md', category: 'custom' }),
    ]);

    const deleted = repo.deleteBySourceAndFilePaths('hacktricks', ['web/sqli.md']);
    expect(deleted).toBe(1);
    expect(repo.count()).toBe(1);
  });
});
