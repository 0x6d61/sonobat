import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { EndpointInputRepository } from '../../../src/db/repository/endpoint-input-repository.js';
import { HostRepository } from '../../../src/db/repository/host-repository.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import { ServiceRepository } from '../../../src/db/repository/service-repository.js';
import { HttpEndpointRepository } from '../../../src/db/repository/http-endpoint-repository.js';
import { InputRepository } from '../../../src/db/repository/input-repository.js';
import type { EndpointInput } from '../../../src/types/entities.js';
import type { CreateEndpointInputInput } from '../../../src/types/repository.js';

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

describe('EndpointInputRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: EndpointInputRepository;
  let endpointRepo: HttpEndpointRepository;
  let inputRepo: InputRepository;
  let serviceId: string;
  let endpointId: string;
  let inputId: string;
  let artifactId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    repo = new EndpointInputRepository(db);
    endpointRepo = new HttpEndpointRepository(db);
    inputRepo = new InputRepository(db);

    // 親レコードを作成: host → artifact → service → endpoint + input
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

    const endpoint = endpointRepo.create({
      serviceId: service.id,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/',
      evidenceArtifactId: artifact.id,
    });
    endpointId = endpoint.id;

    const input = inputRepo.create({
      serviceId: service.id,
      location: 'query',
      name: 'id',
    });
    inputId = input.id;
  });

  it('create — EndpointInput を作成して返す', () => {
    const input: CreateEndpointInputInput = {
      endpointId,
      inputId,
      evidenceArtifactId: artifactId,
    };

    const endpointInput: EndpointInput = repo.create(input);

    expect(endpointInput.id).toBeDefined();
    expect(endpointInput.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(endpointInput.endpointId).toBe(endpointId);
    expect(endpointInput.inputId).toBe(inputId);
    expect(endpointInput.evidenceArtifactId).toBe(artifactId);
    expect(endpointInput.createdAt).toBeDefined();
  });

  it('findById — 存在する EndpointInput を取得する', () => {
    const input: CreateEndpointInputInput = {
      endpointId,
      inputId,
      evidenceArtifactId: artifactId,
    };

    const created = repo.create(input);
    const found = repo.findById(created.id);

    expect(found).toBeDefined();
    expect(found!.id).toBe(created.id);
    expect(found!.endpointId).toBe(created.endpointId);
    expect(found!.inputId).toBe(created.inputId);
    expect(found!.evidenceArtifactId).toBe(created.evidenceArtifactId);
    expect(found!.createdAt).toBe(created.createdAt);
  });

  it('findByEndpointId — endpointId で一覧取得', () => {
    // 2つ目の input を作成
    const input2 = inputRepo.create({
      serviceId,
      location: 'query',
      name: 'page',
    });

    const ei1 = repo.create({
      endpointId,
      inputId,
      evidenceArtifactId: artifactId,
    });

    const ei2 = repo.create({
      endpointId,
      inputId: input2.id,
      evidenceArtifactId: artifactId,
    });

    const results: EndpointInput[] = repo.findByEndpointId(endpointId);

    expect(results).toHaveLength(2);

    const ids = results.map((ei) => ei.id);
    expect(ids).toContain(ei1.id);
    expect(ids).toContain(ei2.id);
  });

  it('findByInputId — inputId で一覧取得', () => {
    // 2つ目の endpoint を作成
    const endpoint2 = endpointRepo.create({
      serviceId,
      baseUri: 'http://10.0.0.1:80',
      method: 'POST',
      path: '/api/data',
      evidenceArtifactId: artifactId,
    });

    const ei1 = repo.create({
      endpointId,
      inputId,
      evidenceArtifactId: artifactId,
    });

    const ei2 = repo.create({
      endpointId: endpoint2.id,
      inputId,
      evidenceArtifactId: artifactId,
    });

    const results: EndpointInput[] = repo.findByInputId(inputId);

    expect(results).toHaveLength(2);

    const ids = results.map((ei) => ei.id);
    expect(ids).toContain(ei1.id);
    expect(ids).toContain(ei2.id);
  });

  it('delete — EndpointInput を削除する', () => {
    const input: CreateEndpointInputInput = {
      endpointId,
      inputId,
      evidenceArtifactId: artifactId,
    };

    const created = repo.create(input);

    const deleted = repo.delete(created.id);

    expect(deleted).toBe(true);

    const found = repo.findById(created.id);
    expect(found).toBeUndefined();
  });
});
