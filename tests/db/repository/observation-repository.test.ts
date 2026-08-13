import { beforeEach, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { ObservationRepository } from '../../../src/db/repository/observation-repository.js';

describe('ObservationRepository', () => {
  let db: InstanceType<typeof Database>;
  let artifactId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    artifactId = randomUUID();
    db.prepare(
      `INSERT INTO artifacts (id, tool, kind, path, captured_at)
       VALUES (?, 'worker', 'tool_output', '/tmp/result', ?)`,
    ).run(artifactId, new Date().toISOString());
  });

  it('ObservationとCredential NodeとEdgeを一つの操作で保存する', () => {
    const result = new ObservationRepository(db).record({
      artifactId,
      actor: 'worker-1',
      content: { summary: 'credential discovered' },
      confidence: 0.9,
      nodes: [
        {
          ref: 'host',
          kind: 'host',
          props: { authorityKind: 'IP', authority: '10.0.0.1' },
        },
        {
          ref: 'credential',
          kind: 'credential',
          props: {
            username: 'admin',
            secret: 'found-value',
            secretType: 'password',
            source: 'worker',
            confidence: 'high',
          },
        },
      ],
      edges: [
        {
          kind: 'SERVICE_CREDENTIAL',
          sourceRef: 'host',
          targetRef: 'credential',
        },
      ],
    });

    expect(result.nodeIds).toHaveLength(2);
    expect(result.edgeIds).toHaveLength(1);
    expect(db.prepare("SELECT COUNT(*) count FROM nodes WHERE kind = 'credential'").get()).toEqual({
      count: 1,
    });
  });

  it('Graphへの反映に失敗した場合はObservationとNodeを残さない', () => {
    const repo = new ObservationRepository(db);
    expect(() =>
      repo.record({
        artifactId,
        actor: 'worker-1',
        content: {},
        nodes: [
          {
            ref: 'host',
            kind: 'host',
            props: { authorityKind: 'IP', authority: '10.0.0.2' },
          },
        ],
        edges: [
          {
            kind: 'HOST_SERVICE',
            sourceRef: 'host',
            targetRef: 'missing-node',
          },
        ],
      }),
    ).toThrow();

    expect(db.prepare('SELECT COUNT(*) count FROM observations').get()).toEqual({ count: 0 });
    expect(db.prepare('SELECT COUNT(*) count FROM nodes').get()).toEqual({ count: 0 });
  });

  it('同じArtifactの同じ解釈を再登録しても重複しない', () => {
    const repo = new ObservationRepository(db);
    const input = {
      artifactId,
      actor: 'worker-1',
      content: { summary: 'same interpretation' },
      nodes: [
        {
          ref: 'credential',
          kind: 'credential',
          props: {
            username: 'admin',
            secret: 'found-value',
            secretType: 'password',
            source: 'worker',
            confidence: 'high',
          },
        },
      ],
    };

    const first = repo.record(input);
    const second = repo.record(input);

    expect(second.id).toBe(first.id);
    expect(db.prepare('SELECT COUNT(*) count FROM observations').get()).toEqual({ count: 1 });
    expect(db.prepare("SELECT COUNT(*) count FROM nodes WHERE kind = 'credential'").get()).toEqual({
      count: 1,
    });
  });
});
