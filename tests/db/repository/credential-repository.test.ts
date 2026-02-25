import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { CredentialRepository } from '../../../src/db/repository/credential-repository.js';
import { HostRepository } from '../../../src/db/repository/host-repository.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import { ServiceRepository } from '../../../src/db/repository/service-repository.js';
import { HttpEndpointRepository } from '../../../src/db/repository/http-endpoint-repository.js';
import type { Credential } from '../../../src/types/entities.js';
import type { CreateCredentialInput } from '../../../src/types/repository.js';

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

describe('CredentialRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: CredentialRepository;
  let serviceId: string;
  let endpointId: string;
  let artifactId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    repo = new CredentialRepository(db);

    // 親レコードを作成: host → artifact → service → http_endpoint
    const hostRepo = new HostRepository(db);
    const artifactRepo = new ArtifactRepository(db);
    const serviceRepo = new ServiceRepository(db);
    const endpointRepo = new HttpEndpointRepository(db);

    const host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });

    const artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/nmap-scan.xml',
      capturedAt: now(),
    });
    artifactId = artifact.id;

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

    const endpoint = endpointRepo.create({
      serviceId: service.id,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/login',
      evidenceArtifactId: artifact.id,
    });
    endpointId = endpoint.id;
  });

  it('create — Credential を作成して返す（service レベル）', () => {
    const input: CreateCredentialInput = {
      serviceId,
      username: 'admin',
      secret: 'password123',
      secretType: 'password',
      source: 'default',
      confidence: 'high',
      evidenceArtifactId: artifactId,
    };

    const credential: Credential = repo.create(input);

    expect(credential.id).toBeDefined();
    expect(credential.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(credential.serviceId).toBe(serviceId);
    expect(credential.endpointId).toBeUndefined();
    expect(credential.username).toBe('admin');
    expect(credential.secret).toBe('password123');
    expect(credential.secretType).toBe('password');
    expect(credential.source).toBe('default');
    expect(credential.confidence).toBe('high');
    expect(credential.evidenceArtifactId).toBe(artifactId);
    expect(credential.createdAt).toBeDefined();
  });

  it('create — Credential を作成して返す（endpoint レベル）', () => {
    const input: CreateCredentialInput = {
      serviceId,
      endpointId,
      username: 'admin',
      secret: 'password123',
      secretType: 'password',
      source: 'default',
      confidence: 'high',
      evidenceArtifactId: artifactId,
    };

    const credential: Credential = repo.create(input);

    expect(credential.id).toBeDefined();
    expect(credential.serviceId).toBe(serviceId);
    expect(credential.endpointId).toBe(endpointId);
    expect(credential.username).toBe('admin');
    expect(credential.secret).toBe('password123');
    expect(credential.secretType).toBe('password');
    expect(credential.source).toBe('default');
    expect(credential.confidence).toBe('high');
    expect(credential.evidenceArtifactId).toBe(artifactId);
    expect(credential.createdAt).toBeDefined();
  });

  it('findById — 存在する Credential を取得する', () => {
    const input: CreateCredentialInput = {
      serviceId,
      username: 'root',
      secret: 'toor',
      secretType: 'password',
      source: 'brute_force',
      confidence: 'medium',
      evidenceArtifactId: artifactId,
    };

    const created = repo.create(input);
    const found = repo.findById(created.id);

    expect(found).toBeDefined();
    expect(found!.id).toBe(created.id);
    expect(found!.serviceId).toBe(created.serviceId);
    expect(found!.username).toBe(created.username);
    expect(found!.secret).toBe(created.secret);
    expect(found!.secretType).toBe(created.secretType);
    expect(found!.source).toBe(created.source);
    expect(found!.confidence).toBe(created.confidence);
    expect(found!.evidenceArtifactId).toBe(created.evidenceArtifactId);
    expect(found!.createdAt).toBe(created.createdAt);
  });

  it('findById — 存在しない場合 undefined を返す', () => {
    const found = repo.findById(crypto.randomUUID());

    expect(found).toBeUndefined();
  });

  it('findByServiceId — serviceId で一覧取得', () => {
    const input1: CreateCredentialInput = {
      serviceId,
      username: 'admin',
      secret: 'password123',
      secretType: 'password',
      source: 'default',
      confidence: 'high',
      evidenceArtifactId: artifactId,
    };
    const input2: CreateCredentialInput = {
      serviceId,
      username: 'root',
      secret: 'toor',
      secretType: 'password',
      source: 'brute_force',
      confidence: 'medium',
      evidenceArtifactId: artifactId,
    };

    const cred1 = repo.create(input1);
    const cred2 = repo.create(input2);

    const results = repo.findByServiceId(serviceId);

    expect(results).toHaveLength(2);
    const ids = results.map((c) => c.id);
    expect(ids).toContain(cred1.id);
    expect(ids).toContain(cred2.id);
  });

  it('findAll — 全 Credential を取得する', () => {
    // 2つ目の service を作成
    const hostRepo = new HostRepository(db);
    const artifactRepo = new ArtifactRepository(db);
    const serviceRepo = new ServiceRepository(db);

    const host2 = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.2',
      resolvedIpsJson: '[]',
    });
    const artifact2 = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/nmap-scan2.xml',
      capturedAt: now(),
    });
    const service2 = serviceRepo.create({
      hostId: host2.id,
      transport: 'tcp',
      port: 22,
      appProto: 'ssh',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact2.id,
    });

    const cred1 = repo.create({
      serviceId,
      username: 'admin',
      secret: 'password123',
      secretType: 'password',
      source: 'default',
      confidence: 'high',
      evidenceArtifactId: artifactId,
    });
    const cred2 = repo.create({
      serviceId: service2.id,
      username: 'root',
      secret: 'toor',
      secretType: 'password',
      source: 'brute_force',
      confidence: 'medium',
      evidenceArtifactId: artifact2.id,
    });

    const results = repo.findAll();

    expect(results).toHaveLength(2);
    const ids = results.map((c) => c.id);
    expect(ids).toContain(cred1.id);
    expect(ids).toContain(cred2.id);
  });

  it('findAll — Credential がない場合は空配列を返す', () => {
    const results = repo.findAll();
    expect(results).toHaveLength(0);
  });

  it('delete — Credential を削除する', () => {
    const input: CreateCredentialInput = {
      serviceId,
      username: 'admin',
      secret: 'password123',
      secretType: 'password',
      source: 'default',
      confidence: 'high',
      evidenceArtifactId: artifactId,
    };

    const created = repo.create(input);

    const deleted = repo.delete(created.id);

    expect(deleted).toBe(true);

    const found = repo.findById(created.id);
    expect(found).toBeUndefined();
  });
});
