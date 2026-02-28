import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { ScanRepository } from '../../../src/db/repository/scan-repository.js';
import type { Scan } from '../../../src/types/entities.js';
import type { CreateScanInput } from '../../../src/types/repository.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

/** テスト用の ISO 8601 タイムスタンプを返す */
function now(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('ScanRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: ScanRepository;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    repo = new ScanRepository(db);
  });

  it('create - Scan を作成して返す', () => {
    const input: CreateScanInput = {
      startedAt: now(),
      finishedAt: now(),
      notes: 'テストスキャン',
    };

    const scan: Scan = repo.create(input);

    expect(scan.id).toBeDefined();
    expect(scan.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(scan.startedAt).toBe(input.startedAt);
    expect(scan.finishedAt).toBe(input.finishedAt);
    expect(scan.notes).toBe(input.notes);
  });

  it('findById - 存在する Scan を取得する', () => {
    const input: CreateScanInput = {
      startedAt: now(),
      finishedAt: now(),
      notes: '検索テスト用スキャン',
    };

    const created = repo.create(input);
    const found = repo.findById(created.id);

    expect(found).toBeDefined();
    expect(found!.id).toBe(created.id);
    expect(found!.startedAt).toBe(created.startedAt);
    expect(found!.finishedAt).toBe(created.finishedAt);
    expect(found!.notes).toBe(created.notes);
  });

  it('findById - 存在しない場合 undefined を返す', () => {
    const found = repo.findById(crypto.randomUUID());

    expect(found).toBeUndefined();
  });

  it('findAll - 全件取得', () => {
    const input1: CreateScanInput = {
      startedAt: now(),
      notes: 'スキャン1',
    };
    const input2: CreateScanInput = {
      startedAt: now(),
      notes: 'スキャン2',
    };

    const scan1 = repo.create(input1);
    const scan2 = repo.create(input2);

    const all: Scan[] = repo.findAll();

    expect(all).toHaveLength(2);

    const ids = all.map((s) => s.id);
    expect(ids).toContain(scan1.id);
    expect(ids).toContain(scan2.id);
  });

  it('create - finishedAt と notes が省略可能', () => {
    const input: CreateScanInput = {
      startedAt: now(),
    };

    const scan = repo.create(input);

    expect(scan.id).toBeDefined();
    expect(scan.startedAt).toBe(input.startedAt);
    // finishedAt と notes はオプションなので null または undefined
    expect(scan.finishedAt ?? null).toBeNull();
    expect(scan.notes ?? null).toBeNull();
  });
});
