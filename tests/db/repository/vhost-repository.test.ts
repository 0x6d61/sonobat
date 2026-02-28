import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { HostRepository } from '../../../src/db/repository/host-repository.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import { VhostRepository } from '../../../src/db/repository/vhost-repository.js';
import type { Host, Artifact, Vhost } from '../../../src/types/entities.js';
import type { CreateVhostInput } from '../../../src/types/repository.js';

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('VhostRepository', () => {
  let db: InstanceType<typeof Database>;
  let hostRepo: HostRepository;
  let artifactRepo: ArtifactRepository;
  let repo: VhostRepository;

  // 共有の親レコード
  let host: Host;
  let artifact: Artifact;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    hostRepo = new HostRepository(db);
    artifactRepo = new ArtifactRepository(db);
    repo = new VhostRepository(db);

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

  it('create — Vhost を作成して返す', () => {
    const input: CreateVhostInput = {
      hostId: host.id,
      hostname: 'example.com',
      source: 'nmap',
      evidenceArtifactId: artifact.id,
    };

    const vhost: Vhost = repo.create(input);

    expect(vhost.id).toBeDefined();
    expect(vhost.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(vhost.hostId).toBe(host.id);
    expect(vhost.hostname).toBe('example.com');
    expect(vhost.source).toBe('nmap');
    expect(vhost.evidenceArtifactId).toBe(artifact.id);
    expect(vhost.createdAt).toBeDefined();
  });

  it('findById — 存在する Vhost を取得する', () => {
    const input: CreateVhostInput = {
      hostId: host.id,
      hostname: 'app.example.com',
      source: 'cert',
      evidenceArtifactId: artifact.id,
    };

    const created = repo.create(input);
    const found = repo.findById(created.id);

    expect(found).toBeDefined();
    expect(found!.id).toBe(created.id);
    expect(found!.hostId).toBe(created.hostId);
    expect(found!.hostname).toBe(created.hostname);
    expect(found!.source).toBe(created.source);
    expect(found!.evidenceArtifactId).toBe(created.evidenceArtifactId);
    expect(found!.createdAt).toBe(created.createdAt);
  });

  it('findById — 存在しない場合 undefined を返す', () => {
    const found = repo.findById(crypto.randomUUID());

    expect(found).toBeUndefined();
  });

  it('findByHostId — hostId で一覧取得', () => {
    const input1: CreateVhostInput = {
      hostId: host.id,
      hostname: 'www.example.com',
      source: 'nmap',
      evidenceArtifactId: artifact.id,
    };

    const input2: CreateVhostInput = {
      hostId: host.id,
      hostname: 'api.example.com',
      source: 'header',
      evidenceArtifactId: artifact.id,
    };

    const vhost1 = repo.create(input1);
    const vhost2 = repo.create(input2);

    const vhosts: Vhost[] = repo.findByHostId(host.id);

    expect(vhosts).toHaveLength(2);

    const ids = vhosts.map((v) => v.id);
    expect(ids).toContain(vhost1.id);
    expect(ids).toContain(vhost2.id);

    const hostnames = vhosts.map((v) => v.hostname);
    expect(hostnames).toContain('www.example.com');
    expect(hostnames).toContain('api.example.com');
  });

  it('delete — Vhost を削除する', () => {
    const input: CreateVhostInput = {
      hostId: host.id,
      hostname: 'temp.example.com',
      source: 'manual',
      evidenceArtifactId: artifact.id,
    };

    const created = repo.create(input);

    const deleted = repo.delete(created.id);

    expect(deleted).toBe(true);

    const found = repo.findById(created.id);
    expect(found).toBeUndefined();
  });
});
