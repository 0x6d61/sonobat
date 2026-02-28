import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { InputRepository } from '../../../src/db/repository/input-repository.js';
import { HostRepository } from '../../../src/db/repository/host-repository.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import { ServiceRepository } from '../../../src/db/repository/service-repository.js';
import type { Input } from '../../../src/types/entities.js';
import type { CreateInputInput, UpdateInputInput } from '../../../src/types/repository.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

/** テスト用の ISO 8601 タイムスタンプを返す */
function now(): string {
  return new Date().toISOString();
}

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

describe('InputRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: InputRepository;
  let serviceId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    repo = new InputRepository(db);

    // 親レコードを作成: host → artifact → service
    const hostRepo = new HostRepository(db);
    const artifactRepo = new ArtifactRepository(db);
    const serviceRepo = new ServiceRepository(db);

    const host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });

    const artifact = artifactRepo.create({
      tool: 'ffuf',
      kind: 'tool_output',
      path: '/tmp/ffuf-result.json',
      capturedAt: now(),
    });

    const service = serviceRepo.create({
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    });
    serviceId = service.id;
  });

  it('create — Input を作成して返す', () => {
    const input: CreateInputInput = {
      serviceId,
      location: 'query',
      name: 'id',
    };

    const created: Input = repo.create(input);

    expect(created.id).toBeDefined();
    expect(created.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(created.serviceId).toBe(serviceId);
    expect(created.location).toBe('query');
    expect(created.name).toBe('id');
    expect(created.typeHint).toBeUndefined();
    expect(created.createdAt).toBeDefined();
    expect(created.updatedAt).toBeDefined();
  });

  it('findById — 存在する Input を取得する', () => {
    const input: CreateInputInput = {
      serviceId,
      location: 'query',
      name: 'page',
    };

    const created = repo.create(input);
    const found = repo.findById(created.id);

    expect(found).toBeDefined();
    expect(found!.id).toBe(created.id);
    expect(found!.serviceId).toBe(created.serviceId);
    expect(found!.location).toBe(created.location);
    expect(found!.name).toBe(created.name);
    expect(found!.createdAt).toBe(created.createdAt);
    expect(found!.updatedAt).toBe(created.updatedAt);
  });

  it('findById — 存在しない場合 undefined を返す', () => {
    const found = repo.findById(crypto.randomUUID());

    expect(found).toBeUndefined();
  });

  it('findByServiceId — serviceId で一覧取得', () => {
    const input1: CreateInputInput = {
      serviceId,
      location: 'query',
      name: 'id',
    };

    const input2: CreateInputInput = {
      serviceId,
      location: 'query',
      name: 'page',
    };

    const created1 = repo.create(input1);
    const created2 = repo.create(input2);

    const results: Input[] = repo.findByServiceId(serviceId);

    expect(results).toHaveLength(2);

    const ids = results.map((i) => i.id);
    expect(ids).toContain(created1.id);
    expect(ids).toContain(created2.id);

    const names = results.map((i) => i.name);
    expect(names).toContain('id');
    expect(names).toContain('page');
  });

  it('findByServiceId — location で絞り込み', () => {
    const queryInput: CreateInputInput = {
      serviceId,
      location: 'query',
      name: 'search',
    };

    const bodyInput: CreateInputInput = {
      serviceId,
      location: 'body',
      name: 'username',
    };

    const createdQuery = repo.create(queryInput);
    repo.create(bodyInput);

    const queryResults = repo.findByServiceId(serviceId, 'query');

    expect(queryResults).toHaveLength(1);
    expect(queryResults[0].id).toBe(createdQuery.id);
    expect(queryResults[0].location).toBe('query');
    expect(queryResults[0].name).toBe('search');
  });

  it('update — typeHint を更新する', async () => {
    const input: CreateInputInput = {
      serviceId,
      location: 'query',
      name: 'id',
    };

    const created = repo.create(input);
    const originalUpdatedAt = created.updatedAt;

    // タイムスタンプに差が出るよう少し待つ
    await sleep(10);

    const updateInput: UpdateInputInput = {
      typeHint: 'integer',
    };

    const updated = repo.update(created.id, updateInput);

    expect(updated).toBeDefined();
    expect(updated!.id).toBe(created.id);
    expect(updated!.typeHint).toBe('integer');
    // 変更していないフィールドはそのまま
    expect(updated!.serviceId).toBe(serviceId);
    expect(updated!.location).toBe('query');
    expect(updated!.name).toBe('id');
    // updatedAt が更新されていること
    expect(updated!.updatedAt).not.toBe(originalUpdatedAt);
    // createdAt は変わらないこと
    expect(updated!.createdAt).toBe(created.createdAt);
  });

  it('delete — Input を削除する', () => {
    const input: CreateInputInput = {
      serviceId,
      location: 'query',
      name: 'delete-me',
    };

    const created = repo.create(input);

    const deleted = repo.delete(created.id);

    expect(deleted).toBe(true);

    const found = repo.findById(created.id);
    expect(found).toBeUndefined();
  });
});
