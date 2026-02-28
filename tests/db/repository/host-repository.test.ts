import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { HostRepository } from '../../../src/db/repository/host-repository.js';
import type { Host } from '../../../src/types/entities.js';
import type { CreateHostInput, UpdateHostInput } from '../../../src/types/repository.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

/**
 * 短い待機を挟んで updatedAt の差分を検出しやすくする。
 * SQLite の TEXT タイムスタンプは ISO 8601 (ミリ秒精度) なので
 * 最低でも 1ms 以上の間隔を空ける。
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('HostRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: HostRepository;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    repo = new HostRepository(db);
  });

  it('create - Host を作成して返す', () => {
    const input: CreateHostInput = {
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    };

    const host: Host = repo.create(input);

    expect(host.id).toBeDefined();
    expect(host.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(host.authorityKind).toBe(input.authorityKind);
    expect(host.authority).toBe(input.authority);
    expect(host.resolvedIpsJson).toBe(input.resolvedIpsJson);
    expect(host.createdAt).toBeDefined();
    expect(host.updatedAt).toBeDefined();
  });

  it('findById - 存在する Host を取得する', () => {
    const input: CreateHostInput = {
      authorityKind: 'IP',
      authority: '192.168.1.1',
      resolvedIpsJson: '[]',
    };

    const created = repo.create(input);
    const found = repo.findById(created.id);

    expect(found).toBeDefined();
    expect(found!.id).toBe(created.id);
    expect(found!.authorityKind).toBe(created.authorityKind);
    expect(found!.authority).toBe(created.authority);
    expect(found!.resolvedIpsJson).toBe(created.resolvedIpsJson);
    expect(found!.createdAt).toBe(created.createdAt);
    expect(found!.updatedAt).toBe(created.updatedAt);
  });

  it('findById - 存在しない場合 undefined を返す', () => {
    const found = repo.findById(crypto.randomUUID());

    expect(found).toBeUndefined();
  });

  it('findAll - 全件取得', () => {
    const input1: CreateHostInput = {
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    };
    const input2: CreateHostInput = {
      authorityKind: 'DOMAIN',
      authority: 'example.com',
      resolvedIpsJson: '["93.184.216.34"]',
    };

    const host1 = repo.create(input1);
    const host2 = repo.create(input2);

    const all: Host[] = repo.findAll();

    expect(all).toHaveLength(2);

    const ids = all.map((h) => h.id);
    expect(ids).toContain(host1.id);
    expect(ids).toContain(host2.id);
  });

  it('findByAuthority - authority で検索', () => {
    const input: CreateHostInput = {
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    };

    const created = repo.create(input);
    const found = repo.findByAuthority('10.0.0.1');

    expect(found).toBeDefined();
    expect(found!.id).toBe(created.id);
    expect(found!.authority).toBe('10.0.0.1');
  });

  it('findByAuthority - 見つからない場合 undefined', () => {
    const found = repo.findByAuthority('nonexistent');

    expect(found).toBeUndefined();
  });

  it('update - resolvedIpsJson を更新する', () => {
    const input: CreateHostInput = {
      authorityKind: 'DOMAIN',
      authority: 'target.local',
      resolvedIpsJson: '[]',
    };

    const created = repo.create(input);

    const updateInput: UpdateHostInput = {
      resolvedIpsJson: '["10.0.0.50", "10.0.0.51"]',
    };

    const updated = repo.update(created.id, updateInput);

    expect(updated).toBeDefined();
    expect(updated!.id).toBe(created.id);
    expect(updated!.resolvedIpsJson).toBe('["10.0.0.50", "10.0.0.51"]');
    // authority は変わっていないこと
    expect(updated!.authority).toBe(created.authority);
  });

  it('update - updatedAt が更新される', async () => {
    const input: CreateHostInput = {
      authorityKind: 'IP',
      authority: '172.16.0.1',
      resolvedIpsJson: '[]',
    };

    const created = repo.create(input);
    const originalUpdatedAt = created.updatedAt;

    // タイムスタンプに差が出るよう少し待つ
    await sleep(10);

    const updateInput: UpdateHostInput = {
      resolvedIpsJson: '["172.16.0.1"]',
    };

    const updated = repo.update(created.id, updateInput);

    expect(updated).toBeDefined();
    expect(updated!.updatedAt).not.toBe(originalUpdatedAt);
    // createdAt は変わらないこと
    expect(updated!.createdAt).toBe(created.createdAt);
  });

  it('delete - Host を削除する', () => {
    const input: CreateHostInput = {
      authorityKind: 'IP',
      authority: '10.0.0.99',
      resolvedIpsJson: '[]',
    };

    const created = repo.create(input);

    const deleted = repo.delete(created.id);

    expect(deleted).toBe(true);

    const found = repo.findById(created.id);
    expect(found).toBeUndefined();
  });
});
