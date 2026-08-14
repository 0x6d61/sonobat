import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';
import { MissionRepository } from '../../../src/db/repository/mission-repository.js';
import { ActionRepository } from '../../../src/db/repository/action-repository.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import {
  EntityRepository,
  RelationRepository,
} from '../../../src/db/repository/entity-repository.js';
import { HypothesisRepository } from '../../../src/db/repository/hypothesis-repository.js';

describe('domain repositories', () => {
  let db: InstanceType<typeof Database>;
  let root: string;
  let engagementId: string;
  let missionId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    root = mkdtempSync(join(tmpdir(), 'sonobat-artifacts-'));
    engagementId = new EngagementRepository(db).create({ name: 'test' }).id;
    missionId = new MissionRepository(db).create({ engagementId, objective: 'test web' }).id;
  });

  afterEach(() => {
    db.close();
    rmSync(root, { recursive: true, force: true });
  });

  it('stores Credential kinds and returns the value', () => {
    const entities = new EntityRepository(db);
    const credential = entities.upsert({
      kind: 'credential',
      naturalKey: 'credential:alice@example',
      properties: { kind: 'password_hash', principal: 'alice', value: 'hash-value' },
    }).entity;
    expect(entities.findById(credential.id)?.properties).toMatchObject({
      kind: 'password_hash',
      value: 'hash-value',
    });
  });

  it('stores relations between generic Entities', () => {
    const entities = new EntityRepository(db);
    const relations = new RelationRepository(db);
    const credential = entities.upsert({ kind: 'credential', naturalKey: 'credential:a' }).entity;
    const service = entities.upsert({ kind: 'service', naturalKey: 'service:https' }).entity;
    expect(
      relations.upsert({
        kind: 'AUTHENTICATES_TO',
        sourceEntityId: credential.id,
        targetEntityId: service.id,
      }).relation.targetEntityId,
    ).toBe(service.id);
  });

  it('stores only a root-relative Artifact path', () => {
    const action = new ActionRepository(db).create({
      engagementId,
      missionId,
      kind: 'scan',
      dedupeKey: 'scan-1',
    });
    const relativePath = 'actions/' + action.id + '/output.txt';
    mkdirSync(join(root, 'actions', action.id), { recursive: true });
    writeFileSync(join(root, relativePath), 'result');
    const artifacts = new ArtifactRepository(db, { rootDir: root });
    const artifact = artifacts.create({ actionId: action.id, path: relativePath });
    expect(artifact).toEqual({
      id: expect.any(String),
      actionId: action.id,
      path: relativePath,
    });
    expect(artifacts.listByAction(action.id)).toEqual([artifact]);
    expect(() => artifacts.create({ actionId: action.id, path: '/tmp/output.txt' })).toThrow(
      /relative/,
    );
    expect(() => artifacts.resolvePath('../outside')).toThrow(/outside/);
  });

  it('leases Actions and keeps child Actions proposed until adoption', () => {
    const actions = new ActionRepository(db);
    const parent = actions.create({
      engagementId,
      missionId,
      kind: 'web',
      dedupeKey: 'parent',
    });
    expect(actions.poll('worker-1', ['web'])?.id).toBe(parent.id);
    const child = actions.create({
      engagementId,
      missionId,
      parentActionId: parent.id,
      kind: 'verify',
      dedupeKey: 'child',
      state: 'proposed',
    });
    expect(actions.poll('worker-2', ['verify'])).toBeUndefined();
    expect(actions.adopt(child.id)?.state).toBe('queued');
  });

  it('records validated and dismissed attack hypotheses', () => {
    const hypotheses = new HypothesisRepository(db);
    const hypothesis = hypotheses.create({
      engagementId,
      missionId,
      title: 'credential reuse',
      objective: 'obtain initial access',
      preconditions: ['credential is valid'],
    });
    const dismissed = hypotheses.evaluate({
      id: hypothesis.id,
      status: 'dismissed',
      validationResult: { attempted: false },
      reason: 'cost exceeds expected value',
    });
    expect(dismissed.status).toBe('dismissed');
    expect(dismissed.dismissalReason).toBe('cost exceeds expected value');
  });
});
