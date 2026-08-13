import { describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';
import { MissionRepository } from '../../../src/db/repository/mission-repository.js';
import { ActionQueueRepository } from '../../../src/db/repository/action-queue-repository.js';
import { ActionExecutionRepository } from '../../../src/db/repository/action-execution-repository.js';
import { ObservationRepository } from '../../../src/db/repository/observation-repository.js';
import { FindingRepository } from '../../../src/db/repository/finding-repository.js';
import { ActionContextRepository } from '../../../src/db/repository/action-context-repository.js';

describe('ActionContextRepository', () => {
  it('scope、親Action、Execution、Observation、Artifact、Findingを返す', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const engagement = new EngagementRepository(db).create({
      name: 'test',
      scopeJson: '{"hosts":["10.0.0.1"]}',
      policyJson: '{"allowActiveTesting":true}',
    });
    const mission = new MissionRepository(db).create({
      engagementId: engagement.id,
      objective: '対象を調査する',
    });
    const actions = new ActionQueueRepository(db);
    const parent = actions.enqueue({
      engagementId: engagement.id,
      missionId: mission.id,
      kind: 'network_service_discovery',
      dedupeKey: 'parent',
    });
    const action = actions.enqueue({
      engagementId: engagement.id,
      parentActionId: parent.id,
      kind: 'web_endpoint_discovery',
      dedupeKey: 'child',
    });
    const execution = new ActionExecutionRepository(db).create({
      actionId: action.id,
      executor: 'worker-1',
    });
    const artifactId = randomUUID();
    db.prepare(
      `INSERT INTO artifacts
       (id, tool, kind, path, captured_at, engagement_id, mission_id, action_id,
        action_execution_id, sensitivity)
       VALUES (?, 'worker-1', 'stdout', 'artifact://stdout', ?, ?, ?, ?, ?, 'internal')`,
    ).run(artifactId, new Date().toISOString(), engagement.id, mission.id, action.id, execution.id);
    const observation = new ObservationRepository(db).record({
      artifactId,
      actor: 'worker-1',
      content: { summary: 'host found' },
      nodes: [{ ref: 'host', kind: 'host', props: { authorityKind: 'IP', authority: '10.0.0.1' } }],
    });
    const finding = new FindingRepository(db).upsert({
      engagementId: engagement.id,
      canonicalKey: 'host-exposed',
      nodeId: observation.nodeIds[0],
      title: 'Host exposed',
      severity: 'info',
      confidence: 'high',
    }).finding;

    const context = new ActionContextRepository(db).get(action.id, observation.nodeIds)!;

    expect(context.engagement.scopeJson).toContain('10.0.0.1');
    expect(context.parentAction?.id).toBe(parent.id);
    expect(context.executions.map((item) => item.id)).toContain(execution.id);
    expect(context.observations.map((item) => item.id)).toContain(observation.id);
    expect(context.artifacts.map((item) => item.id)).toContain(artifactId);
    expect(context.findings.map((item) => item.id)).toContain(finding.id);
  });

  it('Credentialとsecret Artifactは明示的に要求した場合だけ返す', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const engagement = new EngagementRepository(db).create({ name: 'test' });
    const mission = new MissionRepository(db).create({
      engagementId: engagement.id,
      objective: '認証を調査する',
    });
    const action = new ActionQueueRepository(db).enqueue({
      engagementId: engagement.id,
      missionId: mission.id,
      kind: 'credential_validation',
      dedupeKey: 'credential',
    });
    const artifactId = randomUUID();
    db.prepare(
      `INSERT INTO artifacts (id, tool, kind, path, captured_at, engagement_id, mission_id,
       action_id, sensitivity) VALUES (?, 'worker', 'stdout', 'artifact://secret', ?, ?, ?, ?, 'secret')`,
    ).run(artifactId, new Date().toISOString(), engagement.id, mission.id, action.id);
    const observation = new ObservationRepository(db).record({
      artifactId,
      actor: 'worker',
      content: {},
      nodes: [
        {
          ref: 'credential',
          kind: 'credential',
          props: {
            username: 'admin',
            secret: 'value',
            secretType: 'password',
            source: 'worker',
            confidence: 'high',
          },
        },
      ],
    });
    const repo = new ActionContextRepository(db);

    expect(repo.get(action.id, observation.nodeIds)?.nodes).toHaveLength(0);
    const sensitive = repo.get(action.id, observation.nodeIds, { includeSensitive: true });
    expect(sensitive?.nodes[0].kind).toBe('credential');
    expect(sensitive?.artifacts[0].sensitivity).toBe('secret');
  });
});
