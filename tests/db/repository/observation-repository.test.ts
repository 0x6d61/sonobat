import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { ObservationRepository } from '../../../src/db/repository/observation-repository.js';
import { HostRepository } from '../../../src/db/repository/host-repository.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import { ServiceRepository } from '../../../src/db/repository/service-repository.js';
import { InputRepository } from '../../../src/db/repository/input-repository.js';
import type { Observation } from '../../../src/types/entities.js';
import type { CreateObservationInput } from '../../../src/types/repository.js';

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

describe('ObservationRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: ObservationRepository;
  let inputId: string;
  let artifactId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    repo = new ObservationRepository(db);

    // 親レコードを作成: host → artifact → service → input
    const hostRepo = new HostRepository(db);
    const artifactRepo = new ArtifactRepository(db);
    const serviceRepo = new ServiceRepository(db);
    const inputRepo = new InputRepository(db);

    const host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });

    const artifact = artifactRepo.create({
      tool: 'manual',
      kind: 'observation',
      path: '/tmp/manual-observation.json',
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

    const input = inputRepo.create({
      serviceId: service.id,
      location: 'query',
      name: 'username',
    });
    inputId = input.id;
  });

  it('create — Observation を作成して返す', () => {
    const observedAt = now();
    const input: CreateObservationInput = {
      inputId,
      rawValue: 'admin',
      normValue: 'admin',
      source: 'manual',
      confidence: 'high',
      evidenceArtifactId: artifactId,
      observedAt,
    };

    const observation: Observation = repo.create(input);

    expect(observation.id).toBeDefined();
    expect(observation.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(observation.inputId).toBe(inputId);
    expect(observation.rawValue).toBe('admin');
    expect(observation.normValue).toBe('admin');
    expect(observation.bodyPath).toBeUndefined();
    expect(observation.source).toBe('manual');
    expect(observation.confidence).toBe('high');
    expect(observation.evidenceArtifactId).toBe(artifactId);
    expect(observation.observedAt).toBe(observedAt);
  });

  it('findById — 存在する Observation を取得する', () => {
    const observedAt = now();
    const input: CreateObservationInput = {
      inputId,
      rawValue: 'test_user',
      normValue: 'test_user',
      source: 'http_response',
      confidence: 'medium',
      evidenceArtifactId: artifactId,
      observedAt,
    };

    const created = repo.create(input);
    const found = repo.findById(created.id);

    expect(found).toBeDefined();
    expect(found!.id).toBe(created.id);
    expect(found!.inputId).toBe(created.inputId);
    expect(found!.rawValue).toBe(created.rawValue);
    expect(found!.normValue).toBe(created.normValue);
    expect(found!.source).toBe(created.source);
    expect(found!.confidence).toBe(created.confidence);
    expect(found!.evidenceArtifactId).toBe(created.evidenceArtifactId);
    expect(found!.observedAt).toBe(created.observedAt);
  });

  it('findById — 存在しない場合 undefined を返す', () => {
    const found = repo.findById(crypto.randomUUID());

    expect(found).toBeUndefined();
  });

  it('findByInputId — inputId で一覧取得', () => {
    const input1: CreateObservationInput = {
      inputId,
      rawValue: 'admin',
      normValue: 'admin',
      source: 'manual',
      confidence: 'high',
      evidenceArtifactId: artifactId,
      observedAt: now(),
    };

    const input2: CreateObservationInput = {
      inputId,
      rawValue: 'root',
      normValue: 'root',
      source: 'brute_force',
      confidence: 'medium',
      evidenceArtifactId: artifactId,
      observedAt: now(),
    };

    const obs1 = repo.create(input1);
    const obs2 = repo.create(input2);

    const results: Observation[] = repo.findByInputId(inputId);

    expect(results).toHaveLength(2);

    const ids = results.map((o) => o.id);
    expect(ids).toContain(obs1.id);
    expect(ids).toContain(obs2.id);

    const rawValues = results.map((o) => o.rawValue);
    expect(rawValues).toContain('admin');
    expect(rawValues).toContain('root');
  });

  it('delete — Observation を削除する', () => {
    const input: CreateObservationInput = {
      inputId,
      rawValue: 'delete-me',
      normValue: 'delete-me',
      source: 'manual',
      confidence: 'low',
      evidenceArtifactId: artifactId,
      observedAt: now(),
    };

    const created = repo.create(input);

    const deleted = repo.delete(created.id);

    expect(deleted).toBe(true);

    const found = repo.findById(created.id);
    expect(found).toBeUndefined();
  });
});
