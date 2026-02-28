import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { HttpEndpointRepository } from '../../../src/db/repository/http-endpoint-repository.js';
import { HostRepository } from '../../../src/db/repository/host-repository.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import { ServiceRepository } from '../../../src/db/repository/service-repository.js';
import type { HttpEndpoint } from '../../../src/types/entities.js';
import type { CreateHttpEndpointInput } from '../../../src/types/repository.js';

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

describe('HttpEndpointRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: HttpEndpointRepository;
  let serviceId: string;
  let artifactId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    repo = new HttpEndpointRepository(db);

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
  });

  it('create — HttpEndpoint を作成して返す', () => {
    const input: CreateHttpEndpointInput = {
      serviceId,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/',
      evidenceArtifactId: artifactId,
    };

    const endpoint: HttpEndpoint = repo.create(input);

    expect(endpoint.id).toBeDefined();
    expect(endpoint.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(endpoint.serviceId).toBe(serviceId);
    expect(endpoint.vhostId).toBeUndefined();
    expect(endpoint.baseUri).toBe('http://10.0.0.1:80');
    expect(endpoint.method).toBe('GET');
    expect(endpoint.path).toBe('/');
    expect(endpoint.evidenceArtifactId).toBe(artifactId);
    expect(endpoint.createdAt).toBeDefined();
  });

  it('findById — 存在する HttpEndpoint を取得する', () => {
    const input: CreateHttpEndpointInput = {
      serviceId,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/index.html',
      evidenceArtifactId: artifactId,
    };

    const created = repo.create(input);
    const found = repo.findById(created.id);

    expect(found).toBeDefined();
    expect(found!.id).toBe(created.id);
    expect(found!.serviceId).toBe(created.serviceId);
    expect(found!.baseUri).toBe(created.baseUri);
    expect(found!.method).toBe(created.method);
    expect(found!.path).toBe(created.path);
    expect(found!.evidenceArtifactId).toBe(created.evidenceArtifactId);
    expect(found!.createdAt).toBe(created.createdAt);
  });

  it('findById — 存在しない場合 undefined を返す', () => {
    const found = repo.findById(crypto.randomUUID());

    expect(found).toBeUndefined();
  });

  it('findByServiceId — serviceId で一覧取得', () => {
    const input1: CreateHttpEndpointInput = {
      serviceId,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/',
      evidenceArtifactId: artifactId,
    };

    const input2: CreateHttpEndpointInput = {
      serviceId,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/admin',
      evidenceArtifactId: artifactId,
    };

    const endpoint1 = repo.create(input1);
    const endpoint2 = repo.create(input2);

    const endpoints: HttpEndpoint[] = repo.findByServiceId(serviceId);

    expect(endpoints).toHaveLength(2);

    const ids = endpoints.map((e) => e.id);
    expect(ids).toContain(endpoint1.id);
    expect(ids).toContain(endpoint2.id);

    const paths = endpoints.map((e) => e.path);
    expect(paths).toContain('/');
    expect(paths).toContain('/admin');
  });

  it('delete — HttpEndpoint を削除する', () => {
    const input: CreateHttpEndpointInput = {
      serviceId,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/delete-me',
      evidenceArtifactId: artifactId,
    };

    const created = repo.create(input);

    const deleted = repo.delete(created.id);

    expect(deleted).toBe(true);

    const found = repo.findById(created.id);
    expect(found).toBeUndefined();
  });
});
