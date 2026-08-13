import { beforeEach, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { ObservationRepository } from '../../../src/db/repository/observation-repository.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';

describe('ObservationRepository', () => {
  let db: InstanceType<typeof Database>;
  let artifactId: string;
  let engagementId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    engagementId = new EngagementRepository(db).create({ name: 'test' }).id;
    artifactId = randomUUID();
    db.prepare(
      `INSERT INTO artifacts (id, tool, kind, path, captured_at, engagement_id)
       VALUES (?, 'worker', 'tool_output', '/tmp/result', ?, ?)`,
    ).run(artifactId, new Date().toISOString(), engagementId);
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

  it('ObservationとFindingを一つの操作で作成しArtifactを根拠に記録する', () => {
    const result = new ObservationRepository(db).record({
      artifactId,
      actor: 'worker-1',
      content: { summary: 'critical service exposed' },
      nodes: [
        {
          ref: 'host',
          kind: 'host',
          props: { authorityKind: 'IP', authority: '10.0.0.3' },
        },
      ],
      findings: [
        {
          canonicalKey: 'exposed-service:10.0.0.3',
          title: 'Critical service is exposed',
          severity: 'critical',
          confidence: 'high',
          nodeRef: 'host',
          attrs: { source: 'observation' },
        },
      ],
    });

    expect(result.findingIds).toHaveLength(1);
    expect(
      db
        .prepare('SELECT engagement_id, node_id FROM findings WHERE id = ?')
        .get(result.findingIds[0]),
    ).toEqual({ engagement_id: engagementId, node_id: result.nodeIds[0] });
    expect(
      db
        .prepare('SELECT artifact_id FROM finding_events WHERE finding_id = ?')
        .get(result.findingIds[0]),
    ).toEqual({ artifact_id: artifactId });
  });

  it('同じcanonical keyのFindingを更新して各Observationへ関連付ける', () => {
    const repo = new ObservationRepository(db);
    const common = {
      artifactId,
      actor: 'worker-1',
      findings: [
        {
          canonicalKey: 'finding:shared',
          title: 'Initial title',
          severity: 'medium',
          confidence: 'medium',
        },
      ],
    };
    const first = repo.record({ ...common, content: { pass: 1 } });
    const second = repo.record({
      ...common,
      content: { pass: 2 },
      findings: [{ ...common.findings[0], title: 'Updated title', severity: 'high' }],
    });

    expect(second.findingIds).toEqual(first.findingIds);
    expect(db.prepare('SELECT title, severity FROM findings').get()).toEqual({
      title: 'Updated title',
      severity: 'high',
    });
    expect(db.prepare('SELECT COUNT(*) count FROM finding_events').get()).toEqual({ count: 2 });
    expect(db.prepare('SELECT COUNT(*) count FROM observation_findings').get()).toEqual({
      count: 2,
    });
  });

  it('Findingの反映に失敗した場合はObservation、Graph、Findingを残さない', () => {
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
            props: { authorityKind: 'IP', authority: '10.0.0.4' },
          },
        ],
        findings: [
          {
            canonicalKey: 'valid-before-failure',
            title: 'Would be valid',
            severity: 'low',
            confidence: 'medium',
            nodeRef: 'host',
          },
          {
            canonicalKey: 'invalid-node',
            title: 'Invalid node ref',
            severity: 'high',
            confidence: 'high',
            nodeRef: 'missing-node',
          },
        ],
      }),
    ).toThrow(/Finding node not found/);

    expect(db.prepare('SELECT COUNT(*) count FROM observations').get()).toEqual({ count: 0 });
    expect(db.prepare('SELECT COUNT(*) count FROM nodes').get()).toEqual({ count: 0 });
    expect(db.prepare('SELECT COUNT(*) count FROM findings').get()).toEqual({ count: 0 });
    expect(db.prepare('SELECT COUNT(*) count FROM finding_events').get()).toEqual({ count: 0 });
  });
});
