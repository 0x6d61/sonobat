import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { HostRepository } from '../../../src/db/repository/host-repository.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import { ServiceRepository } from '../../../src/db/repository/service-repository.js';
import { ServiceObservationRepository } from '../../../src/db/repository/service-observation-repository.js';
import type { Host, Artifact, Service, ServiceObservation } from '../../../src/types/entities.js';
import type { CreateServiceObservationInput } from '../../../src/types/repository.js';

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('ServiceObservationRepository', () => {
  let db: InstanceType<typeof Database>;
  let hostRepo: HostRepository;
  let artifactRepo: ArtifactRepository;
  let serviceRepo: ServiceRepository;
  let repo: ServiceObservationRepository;

  // 共有の親レコード
  let host: Host;
  let artifact: Artifact;
  let service: Service;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    hostRepo = new HostRepository(db);
    artifactRepo = new ArtifactRepository(db);
    serviceRepo = new ServiceRepository(db);
    repo = new ServiceObservationRepository(db);

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

    service = serviceRepo.create({
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    });
  });

  it('create — ServiceObservation を作成して返す', () => {
    const input: CreateServiceObservationInput = {
      serviceId: service.id,
      key: 'os',
      value: 'Linux',
      confidence: 'high',
      evidenceArtifactId: artifact.id,
    };

    const observation: ServiceObservation = repo.create(input);

    expect(observation.id).toBeDefined();
    expect(observation.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(observation.serviceId).toBe(service.id);
    expect(observation.key).toBe('os');
    expect(observation.value).toBe('Linux');
    expect(observation.confidence).toBe('high');
    expect(observation.evidenceArtifactId).toBe(artifact.id);
    expect(observation.createdAt).toBeDefined();
  });

  it('findById — 存在する ServiceObservation を取得する', () => {
    const input: CreateServiceObservationInput = {
      serviceId: service.id,
      key: 'server_header',
      value: 'Apache/2.4.41',
      confidence: 'high',
      evidenceArtifactId: artifact.id,
    };

    const created = repo.create(input);
    const found = repo.findById(created.id);

    expect(found).toBeDefined();
    expect(found!.id).toBe(created.id);
    expect(found!.serviceId).toBe(created.serviceId);
    expect(found!.key).toBe(created.key);
    expect(found!.value).toBe(created.value);
    expect(found!.confidence).toBe(created.confidence);
    expect(found!.evidenceArtifactId).toBe(created.evidenceArtifactId);
    expect(found!.createdAt).toBe(created.createdAt);
  });

  it('findByServiceId — serviceId で一覧取得', () => {
    const input1: CreateServiceObservationInput = {
      serviceId: service.id,
      key: 'os',
      value: 'Linux',
      confidence: 'high',
      evidenceArtifactId: artifact.id,
    };

    const input2: CreateServiceObservationInput = {
      serviceId: service.id,
      key: 'server_header',
      value: 'nginx/1.18.0',
      confidence: 'medium',
      evidenceArtifactId: artifact.id,
    };

    const obs1 = repo.create(input1);
    const obs2 = repo.create(input2);

    const observations: ServiceObservation[] = repo.findByServiceId(service.id);

    expect(observations).toHaveLength(2);

    const ids = observations.map((o) => o.id);
    expect(ids).toContain(obs1.id);
    expect(ids).toContain(obs2.id);

    const keys = observations.map((o) => o.key);
    expect(keys).toContain('os');
    expect(keys).toContain('server_header');
  });

  it('delete — ServiceObservation を削除する', () => {
    const input: CreateServiceObservationInput = {
      serviceId: service.id,
      key: 'temp_observation',
      value: 'temporary',
      confidence: 'low',
      evidenceArtifactId: artifact.id,
    };

    const created = repo.create(input);

    const deleted = repo.delete(created.id);

    expect(deleted).toBe(true);

    const found = repo.findById(created.id);
    expect(found).toBeUndefined();
  });
});
