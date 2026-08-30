import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { ActivityRepository } from '../../../src/db/repository/activity-repository.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import { AssessmentRepository } from '../../../src/db/repository/assessment-repository.js';
import {
  EntityRepository,
  RelationRepository,
} from '../../../src/db/repository/entity-repository.js';

describe('core model repositories', () => {
  let db: InstanceType<typeof Database>;
  let root: string;
  let assessmentId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    root = mkdtempSync(join(tmpdir(), 'sonobat-artifacts-'));
    assessmentId = new AssessmentRepository(db).create({ name: 'test' }).id;
  });

  afterEach(() => {
    db.close();
    rmSync(root, { recursive: true, force: true });
  });

  it('creates and lists Assessment namespaces', () => {
    const assessments = new AssessmentRepository(db);
    expect(assessments.findById(assessmentId)).toEqual(
      expect.objectContaining({ id: assessmentId, name: 'test' }),
    );
    expect(assessments.list()).toHaveLength(1);
  });

  it('stores Credential kinds and returns the value', () => {
    const entities = new EntityRepository(db);
    const credential = entities.upsert({
      assessmentId,
      kind: 'credential',
      naturalKey: 'credential:alice@example',
      properties: { kind: 'password_hash', principal: 'alice', value: 'hash-value' },
    }).entity;
    expect(entities.findById(credential.id, assessmentId)?.properties).toMatchObject({
      kind: 'password_hash',
      value: 'hash-value',
    });
  });

  it('stores relations between generic Entities', () => {
    const entities = new EntityRepository(db);
    const relations = new RelationRepository(db);
    const credential = entities.upsert({
      assessmentId,
      kind: 'credential',
      naturalKey: 'credential:a',
    }).entity;
    const service = entities.upsert({
      assessmentId,
      kind: 'service',
      naturalKey: 'service:https',
    }).entity;
    expect(
      relations.upsert({
        assessmentId,
        kind: 'AUTHENTICATES_TO',
        sourceEntityId: credential.id,
        targetEntityId: service.id,
      }).relation.targetEntityId,
    ).toBe(service.id);
  });

  it('keeps Entity natural keys and Relation references inside an Assessment', () => {
    const secondAssessment = new AssessmentRepository(db).create({ name: 'second' });
    const entities = new EntityRepository(db);
    const relations = new RelationRepository(db);
    const firstHost = entities.upsert({
      assessmentId,
      kind: 'host',
      naturalKey: 'host:shared',
    }).entity;
    const secondHost = entities.upsert({
      assessmentId: secondAssessment.id,
      kind: 'host',
      naturalKey: 'host:shared',
    }).entity;

    expect(firstHost.id).not.toBe(secondHost.id);
    expect(entities.list(assessmentId)).toEqual([expect.objectContaining({ id: firstHost.id })]);
    expect(entities.list(secondAssessment.id)).toEqual([
      expect.objectContaining({ id: secondHost.id }),
    ]);
    expect(() =>
      relations.upsert({
        assessmentId,
        kind: 'RELATED_TO',
        sourceEntityId: firstHost.id,
        targetEntityId: secondHost.id,
      }),
    ).toThrow(/same Assessment/);
  });

  it('records an Activity and registers a root-relative Artifact reference', () => {
    const activity = new ActivityRepository(db).record({
      assessmentId,
      kind: 'nmap',
      description: 'nmap -sV target',
      resultSummary: '22/tcp open',
    });
    const relativePath = `activities/${activity.id}/output.txt`;
    mkdirSync(join(root, 'activities', activity.id), { recursive: true });
    writeFileSync(join(root, relativePath), 'result');
    const artifacts = new ArtifactRepository(db, { rootDir: root });
    const artifact = artifacts.create({
      assessmentId,
      activityId: activity.id,
      path: relativePath,
      mediaType: 'text/plain',
    });
    expect(artifact).toEqual(
      expect.objectContaining({
        assessmentId,
        activityId: activity.id,
        path: relativePath,
        mediaType: 'text/plain',
      }),
    );
    expect(artifacts.list(assessmentId, activity.id)).toEqual([artifact]);
    expect(() => artifacts.create({ assessmentId, path: '/tmp/output.txt' })).toThrow(/relative/);
    expect(() => artifacts.resolvePath('../outside')).toThrow(/outside/);
  });
});
