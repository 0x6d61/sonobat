import { beforeEach, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';
import { MissionRepository } from '../../../src/db/repository/mission-repository.js';
import { ActionQueueRepository } from '../../../src/db/repository/action-queue-repository.js';
import { NodeRepository } from '../../../src/db/repository/node-repository.js';

describe('MissionRepository', () => {
  let db: InstanceType<typeof Database>;
  let engagementId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    engagementId = new EngagementRepository(db).create({ name: 'test' }).id;
  });

  it('Missionを作成し、所属Actionを登録できる', () => {
    const target = new NodeRepository(db).create('host', {
      authorityKind: 'IP',
      authority: '10.0.0.1',
    });
    const mission = new MissionRepository(db).create({
      engagementId,
      objective: 'Webの攻撃面を明らかにする',
      targetsJson: JSON.stringify([{ type: 'node', id: target.id }]),
      successConditionsJson: '["Endpointを記録する"]',
    });
    const action = new ActionQueueRepository(db).enqueue({
      engagementId,
      missionId: mission.id,
      kind: 'endpoint_discovery',
      dedupeKey: 'endpoint:target-1',
    });

    expect(mission.status).toBe('active');
    expect(action.missionId).toBe(mission.id);
  });

  it('Engagementのhost scope外にあるNodeを拒否する', () => {
    const scopedEngagement = new EngagementRepository(db).create({
      name: 'scoped',
      scopeJson: '{"hostAuthorities":["10.0.0.1"]}',
    });
    const outside = new NodeRepository(db).create('host', {
      authorityKind: 'IP',
      authority: '10.0.0.2',
    });

    expect(() =>
      new MissionRepository(db).create({
        engagementId: scopedEngagement.id,
        objective: 'scope外を調査する',
        targetsJson: JSON.stringify([{ type: 'node', id: outside.id }]),
      }),
    ).toThrow(/outside engagement host scope/);
  });

  it('型が不正な対象参照を拒否する', () => {
    expect(() =>
      new MissionRepository(db).create({
        engagementId,
        objective: '不正な対象',
        targetsJson: '[{"type":"port","id":"80"}]',
      }),
    ).toThrow();
  });

  it('子Actionは親のMissionとRunを継承する', () => {
    const mission = new MissionRepository(db).create({
      engagementId,
      objective: '認証面を調査する',
    });
    const actions = new ActionQueueRepository(db);
    const parent = actions.enqueue({
      engagementId,
      missionId: mission.id,
      kind: 'credential_discovery',
      dedupeKey: 'credential:root',
    });
    const child = actions.enqueue({
      engagementId,
      parentActionId: parent.id,
      kind: 'credential_validation',
      dedupeKey: 'credential:child',
    });

    expect(child.missionId).toBe(mission.id);
    expect(child.parentActionId).toBe(parent.id);
  });
});
