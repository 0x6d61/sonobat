import { beforeEach, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';
import { MissionRepository } from '../../../src/db/repository/mission-repository.js';
import { ActionQueueRepository } from '../../../src/db/repository/action-queue-repository.js';
import { WorkerLifecycleRepository } from '../../../src/db/repository/worker-lifecycle-repository.js';

describe('WorkerLifecycleRepository', () => {
  let db: InstanceType<typeof Database>;
  let actions: ActionQueueRepository;
  let lifecycle: WorkerLifecycleRepository;
  let actionId: string;
  let missionId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    const engagement = new EngagementRepository(db).create({ name: 'test' });
    const mission = new MissionRepository(db).create({
      engagementId: engagement.id,
      objective: 'Webの攻撃面を調査する',
    });
    missionId = mission.id;
    actions = new ActionQueueRepository(db);
    const action = actions.enqueue({
      engagementId: engagement.id,
      missionId,
      kind: 'web_endpoint_discovery',
      dedupeKey: 'web:test',
    });
    actionId = action.id;
    actions.poll('worker-1');
    lifecycle = new WorkerLifecycleRepository(db);
  });

  it('lease所有者がExecutionを開始してArtifactを登録できる', () => {
    const execution = lifecycle.startExecution({
      actionId,
      leaseOwner: 'worker-1',
      executor: 'worker-1',
      inputJson: '{"target":"example.test"}',
    });
    const artifact = lifecycle.registerArtifact({
      executionId: execution.id,
      leaseOwner: 'worker-1',
      kind: 'stdout',
      path: 'artifact://stdout',
      sha256: 'abc123',
      mediaType: 'text/plain',
    });

    expect(artifact.actionId).toBe(actionId);
    expect(artifact.missionId).toBe(missionId);
    expect(artifact.actionExecutionId).toBe(execution.id);
  });

  it('別WorkerのleaseではExecutionを開始できない', () => {
    expect(() =>
      lifecycle.startExecution({
        actionId,
        leaseOwner: 'worker-2',
        executor: 'worker-2',
      }),
    ).toThrow(/lease owner/);
  });

  it('期限切れleaseではExecutionを開始できない', () => {
    db.prepare('UPDATE action_queue SET lease_expires_at = ? WHERE id = ?').run(
      '2000-01-01T00:00:00.000Z',
      actionId,
    );
    expect(() =>
      lifecycle.startExecution({
        actionId,
        leaseOwner: 'worker-1',
        executor: 'worker-1',
      }),
    ).toThrow(/expired/);
  });

  it('成功時はExecutionとActionを一つの操作で完了する', () => {
    const execution = lifecycle.startExecution({
      actionId,
      leaseOwner: 'worker-1',
      executor: 'worker-1',
    });

    const result = lifecycle.finishExecution({
      executionId: execution.id,
      leaseOwner: 'worker-1',
      outcome: 'succeeded',
      outputJson: '{"count":3}',
      exitCode: 0,
    });

    expect(result.execution.finishedAt).toBeDefined();
    expect(result.action.state).toBe('succeeded');
    expect(() =>
      lifecycle.finishExecution({
        executionId: execution.id,
        leaseOwner: 'worker-1',
        outcome: 'succeeded',
      }),
    ).toThrow(/already finished/);
  });

  it('失敗時はExecutionへエラーを保存してActionを再試行可能にする', () => {
    const execution = lifecycle.startExecution({
      actionId,
      leaseOwner: 'worker-1',
      executor: 'worker-1',
    });

    const result = lifecycle.finishExecution({
      executionId: execution.id,
      leaseOwner: 'worker-1',
      outcome: 'failed',
      errorType: 'timeout',
      errorMessage: 'request timed out',
    });

    expect(result.execution.errorType).toBe('timeout');
    expect(result.action.state).toBe('queued');
    expect(result.action.lastError).toBe('request timed out');
  });
});
