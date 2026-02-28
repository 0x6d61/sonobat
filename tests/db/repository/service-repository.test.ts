import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { HostRepository } from '../../../src/db/repository/host-repository.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import { ServiceRepository } from '../../../src/db/repository/service-repository.js';
import type { Host, Artifact, Service } from '../../../src/types/entities.js';
import type {
  CreateServiceInput,
  UpdateServiceInput,
} from '../../../src/types/repository.js';

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

describe('ServiceRepository', () => {
  let db: InstanceType<typeof Database>;
  let hostRepo: HostRepository;
  let artifactRepo: ArtifactRepository;
  let repo: ServiceRepository;

  // 共有の親レコード
  let host: Host;
  let artifact: Artifact;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    hostRepo = new HostRepository(db);
    artifactRepo = new ArtifactRepository(db);
    repo = new ServiceRepository(db);

    // FK 依存を満たす親レコードを作成
    host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });

    artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/nmap-output.xml',
      capturedAt: new Date().toISOString(),
    });
  });

  it('create — Service を作成して返す', () => {
    const input: CreateServiceInput = {
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    };

    const service: Service = repo.create(input);

    expect(service.id).toBeDefined();
    expect(service.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(service.hostId).toBe(host.id);
    expect(service.transport).toBe('tcp');
    expect(service.port).toBe(80);
    expect(service.appProto).toBe('http');
    expect(service.protoConfidence).toBe('high');
    expect(service.state).toBe('open');
    expect(service.evidenceArtifactId).toBe(artifact.id);
    expect(service.createdAt).toBeDefined();
    expect(service.updatedAt).toBeDefined();
  });

  it('findById — 存在する Service を取得する', () => {
    const input: CreateServiceInput = {
      hostId: host.id,
      transport: 'tcp',
      port: 443,
      appProto: 'https',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    };

    const created = repo.create(input);
    const found = repo.findById(created.id);

    expect(found).toBeDefined();
    expect(found!.id).toBe(created.id);
    expect(found!.hostId).toBe(created.hostId);
    expect(found!.transport).toBe(created.transport);
    expect(found!.port).toBe(created.port);
    expect(found!.appProto).toBe(created.appProto);
    expect(found!.protoConfidence).toBe(created.protoConfidence);
    expect(found!.state).toBe(created.state);
    expect(found!.evidenceArtifactId).toBe(created.evidenceArtifactId);
    expect(found!.createdAt).toBe(created.createdAt);
    expect(found!.updatedAt).toBe(created.updatedAt);
  });

  it('findById — 存在しない場合 undefined を返す', () => {
    const found = repo.findById(crypto.randomUUID());

    expect(found).toBeUndefined();
  });

  it('findByHostId — hostId で一覧取得', () => {
    const input80: CreateServiceInput = {
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    };

    const input443: CreateServiceInput = {
      hostId: host.id,
      transport: 'tcp',
      port: 443,
      appProto: 'https',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    };

    const service80 = repo.create(input80);
    const service443 = repo.create(input443);

    const services: Service[] = repo.findByHostId(host.id);

    expect(services).toHaveLength(2);

    const ids = services.map((s) => s.id);
    expect(ids).toContain(service80.id);
    expect(ids).toContain(service443.id);

    const ports = services.map((s) => s.port);
    expect(ports).toContain(80);
    expect(ports).toContain(443);
  });

  it('update — appProto, banner 等を更新する', async () => {
    const input: CreateServiceInput = {
      hostId: host.id,
      transport: 'tcp',
      port: 8080,
      appProto: 'unknown',
      protoConfidence: 'low',
      state: 'open',
      evidenceArtifactId: artifact.id,
    };

    const created = repo.create(input);
    const originalUpdatedAt = created.updatedAt;

    // タイムスタンプに差が出るよう少し待つ
    await sleep(10);

    const updateInput: UpdateServiceInput = {
      appProto: 'http',
      banner: 'Apache/2.4.41',
    };

    const updated = repo.update(created.id, updateInput);

    expect(updated).toBeDefined();
    expect(updated!.id).toBe(created.id);
    expect(updated!.appProto).toBe('http');
    expect(updated!.banner).toBe('Apache/2.4.41');
    // 変更していないフィールドはそのまま
    expect(updated!.transport).toBe('tcp');
    expect(updated!.port).toBe(8080);
    expect(updated!.state).toBe('open');
    // updatedAt が更新されていること
    expect(updated!.updatedAt).not.toBe(originalUpdatedAt);
    // createdAt は変わらないこと
    expect(updated!.createdAt).toBe(created.createdAt);
  });

  it('delete — Service を削除する', () => {
    const input: CreateServiceInput = {
      hostId: host.id,
      transport: 'tcp',
      port: 22,
      appProto: 'ssh',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    };

    const created = repo.create(input);

    const deleted = repo.delete(created.id);

    expect(deleted).toBe(true);

    const found = repo.findById(created.id);
    expect(found).toBeUndefined();
  });
});
