import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';
import { MissionRepository } from '../../../src/db/repository/mission-repository.js';
import { ActionQueueRepository } from '../../../src/db/repository/action-queue-repository.js';
import { WorkerLifecycleRepository } from '../../../src/db/repository/worker-lifecycle-repository.js';
import { NodeRepository } from '../../../src/db/repository/node-repository.js';

describe('WorkerLifecycleRepository', () => {
  let db: InstanceType<typeof Database>;
  let actions: ActionQueueRepository;
  let lifecycle: WorkerLifecycleRepository;
  let actionId: string;
  let missionId: string;
  let artifactRoot: string;
  let parentTargetId: string;
  let outsideParentTargetId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    artifactRoot = mkdtempSync(join(tmpdir(), 'sonobat-worker-test-'));
    migrateDatabase(db);
    const engagement = new EngagementRepository(db).create({ name: 'test' });
    const mission = new MissionRepository(db).create({
      engagementId: engagement.id,
      objective: 'Webの攻撃面を調査する',
    });
    missionId = mission.id;
    const nodes = new NodeRepository(db);
    parentTargetId = nodes.upsert('host', {
      authorityKind: 'IP',
      authority: '192.0.2.1',
    }).node.id;
    outsideParentTargetId = nodes.upsert('host', {
      authorityKind: 'IP',
      authority: '192.0.2.2',
    }).node.id;
    actions = new ActionQueueRepository(db);
    const action = actions.enqueue({
      engagementId: engagement.id,
      missionId,
      kind: 'web_endpoint_discovery',
      dedupeKey: 'web:test',
      paramsJson: JSON.stringify({ targets: [{ type: 'node', id: parentTargetId }] }),
    });
    actionId = action.id;
    actions.poll('worker-1');
    lifecycle = new WorkerLifecycleRepository(db, { rootDir: artifactRoot });
  });

  afterEach(() => {
    db.close();
    rmSync(artifactRoot, { recursive: true, force: true });
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
      path: 'stdout.txt',
      contentBase64: Buffer.from('command output').toString('base64'),
      mediaType: 'text/plain',
    });

    expect(artifact.actionId).toBe(actionId);
    expect(artifact.missionId).toBe(missionId);
    expect(artifact.actionExecutionId).toBe(execution.id);
    expect(artifact.path.startsWith(artifactRoot)).toBe(true);
    expect(artifact.sha256).toMatch(/^[a-f0-9]{64}$/);
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

  it('子Actionをproposedで登録し親のMissionを継承する', () => {
    const execution = lifecycle.startExecution({
      actionId,
      leaseOwner: 'worker-1',
      executor: 'worker-1',
    });

    const child = lifecycle.proposeChildAction({
      executionId: execution.id,
      leaseOwner: 'worker-1',
      kind: 'http_service_review',
      dedupeKey: 'child:review',
    });

    expect(child.state).toBe('proposed');
    expect(child.parentActionId).toBe(actionId);
    expect(child.missionId).toBe(missionId);
    expect(JSON.parse(child.paramsJson)).toMatchObject({
      targets: [{ type: 'node', id: parentTargetId }],
    });
    expect(actions.poll('worker-2', 300, ['http_service_review'])).toBeUndefined();
  });

  it('別Workerは子Actionを提案できない', () => {
    const execution = lifecycle.startExecution({
      actionId,
      leaseOwner: 'worker-1',
      executor: 'worker-1',
    });

    expect(() =>
      lifecycle.proposeChildAction({
        executionId: execution.id,
        leaseOwner: 'worker-2',
        kind: 'http_service_review',
        dedupeKey: 'child:invalid-worker',
      }),
    ).toThrow(/lease owner/);
  });

  it('親Actionの対象範囲外にある子Actionを拒否する', () => {
    const execution = lifecycle.startExecution({
      actionId,
      leaseOwner: 'worker-1',
      executor: 'worker-1',
    });

    expect(() =>
      lifecycle.proposeChildAction({
        executionId: execution.id,
        leaseOwner: 'worker-1',
        kind: 'http_service_review',
        dedupeKey: 'child:outside-parent',
        paramsJson: JSON.stringify({
          targets: [{ type: 'node', id: outsideParentTargetId }],
        }),
      }),
    ).toThrow(/outside parent action scope/);
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
