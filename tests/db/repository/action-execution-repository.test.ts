import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { ActionExecutionRepository } from '../../../src/db/repository/action-execution-repository.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';
import type { ActionExecution } from '../../../src/types/operational.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

/** テスト用 :memory: DB を作成しマイグレーション済みで返す */
function createTestDb(): InstanceType<typeof Database> {
  const db = new Database(':memory:');
  migrateDatabase(db);
  return db;
}

/** テスト用 engagement を作成し id を返す */
function insertTestEngagement(db: InstanceType<typeof Database>): string {
  const repo = new EngagementRepository(db);
  return repo.create({ name: 'Test Engagement' }).id;
}

/** テスト用 action_queue レコードを挿入し id を返す */
function insertTestAction(
  db: InstanceType<typeof Database>,
  engagementId: string,
  runId?: string,
): string {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO action_queue (id, engagement_id, run_id, kind, priority, dedupe_key, params_json, state, attempt_count, max_attempts, available_at, created_at, updated_at)
     VALUES (?, ?, ?, 'nmap_scan', 100, ?, '{}', 'queued', 0, 3, ?, ?, ?)`,
  ).run(id, engagementId, runId ?? null, `dedupe-${id}`, now, now, now);
  return id;
}

/** テスト用 run レコードを挿入し id を返す */
function insertTestRun(db: InstanceType<typeof Database>, engagementId: string): string {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO runs (id, engagement_id, trigger_kind, status, summary_json, created_at)
     VALUES (?, ?, 'manual', 'running', '{}', ?)`,
  ).run(id, engagementId, now);
  return id;
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('ActionExecutionRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: ActionExecutionRepository;
  let engagementId: string;
  let actionId: string;

  beforeEach(() => {
    db = createTestDb();
    repo = new ActionExecutionRepository(db);
    engagementId = insertTestEngagement(db);
    actionId = insertTestAction(db, engagementId);
  });

  // =======================================================================
  // create()
  // =======================================================================

  describe('create()', () => {
    it('基本作成 — creates execution with all fields verified, started_at=now, inputJson defaults to {}', () => {
      const exec = repo.create({
        actionId,
        executor: 'nmap-executor',
        command: 'nmap -sV 10.0.0.1',
        inputJson: '{"target":"10.0.0.1"}',
      });

      expect(exec.id).toBeDefined();
      expect(exec.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
      expect(exec.actionId).toBe(actionId);
      expect(exec.executor).toBe('nmap-executor');
      expect(exec.command).toBe('nmap -sV 10.0.0.1');
      expect(exec.inputJson).toBe('{"target":"10.0.0.1"}');
      expect(exec.outputJson).toBe('{}');
      expect(exec.startedAt).toBeDefined();
      // startedAt should be a valid ISO string
      expect(() => new Date(exec.startedAt)).not.toThrow();
      expect(exec.finishedAt).toBeUndefined();
      expect(exec.durationMs).toBeUndefined();
      expect(exec.exitCode).toBeUndefined();
      expect(exec.errorType).toBeUndefined();
      expect(exec.errorMessage).toBeUndefined();
      expect(exec.stdoutArtifactId).toBeUndefined();
      expect(exec.stderrArtifactId).toBeUndefined();
    });

    it('デフォルト値 — inputJson={}, outputJson={}, no exit_code/error/finished_at/duration', () => {
      const exec = repo.create({
        actionId,
        executor: 'nuclei-executor',
      });

      expect(exec.inputJson).toBe('{}');
      expect(exec.outputJson).toBe('{}');
      expect(exec.command).toBeUndefined();
      expect(exec.runId).toBeUndefined();
      expect(exec.exitCode).toBeUndefined();
      expect(exec.errorType).toBeUndefined();
      expect(exec.errorMessage).toBeUndefined();
      expect(exec.finishedAt).toBeUndefined();
      expect(exec.durationMs).toBeUndefined();
    });
  });

  // =======================================================================
  // findById()
  // =======================================================================

  describe('findById()', () => {
    it('存在するID — returns the execution', () => {
      const created = repo.create({
        actionId,
        executor: 'nmap-executor',
        command: 'nmap -sV 10.0.0.1',
      });

      const found = repo.findById(created.id);

      expect(found).toBeDefined();
      expect(found!.id).toBe(created.id);
      expect(found!.actionId).toBe(actionId);
      expect(found!.executor).toBe('nmap-executor');
      expect(found!.command).toBe('nmap -sV 10.0.0.1');
      expect(found!.startedAt).toBe(created.startedAt);
    });

    it('存在しないID — returns undefined', () => {
      const found = repo.findById(crypto.randomUUID());
      expect(found).toBeUndefined();
    });
  });

  // =======================================================================
  // findByAction()
  // =======================================================================

  describe('findByAction()', () => {
    it('アクションフィルタ — returns executions for given action_id, ordered by started_at DESC', () => {
      const actionId2 = insertTestAction(db, engagementId);

      // action 1 に 2 件作成（started_at に明確な時間差を設ける）
      const execId1 = crypto.randomUUID();
      const execId2 = crypto.randomUUID();

      db.prepare(
        `INSERT INTO action_executions (id, action_id, executor, input_json, output_json, started_at)
         VALUES (?, ?, 'exec-1', '{}', '{}', ?)`,
      ).run(execId1, actionId, '2026-01-01T00:00:00.000Z');

      db.prepare(
        `INSERT INTO action_executions (id, action_id, executor, input_json, output_json, started_at)
         VALUES (?, ?, 'exec-2', '{}', '{}', ?)`,
      ).run(execId2, actionId, '2026-01-02T00:00:00.000Z');

      // action 2 に 1 件作成
      repo.create({ actionId: actionId2, executor: 'other-executor' });

      const executions = repo.findByAction(actionId);

      expect(executions).toHaveLength(2);
      expect(executions.every((e: ActionExecution) => e.actionId === actionId)).toBe(true);

      // started_at DESC 順：execId2 が先（より新しい）
      expect(executions[0].id).toBe(execId2);
      expect(executions[1].id).toBe(execId1);
    });
  });

  // =======================================================================
  // findByRun()
  // =======================================================================

  describe('findByRun()', () => {
    it('ランフィルタ — returns executions for given run_id, ordered by started_at DESC', () => {
      const runId1 = insertTestRun(db, engagementId);
      const runId2 = insertTestRun(db, engagementId);

      // run 1 に 2 件作成（started_at に明確な時間差を設ける）
      const execId1 = crypto.randomUUID();
      const execId2 = crypto.randomUUID();

      db.prepare(
        `INSERT INTO action_executions (id, action_id, run_id, executor, input_json, output_json, started_at)
         VALUES (?, ?, ?, 'exec-1', '{}', '{}', ?)`,
      ).run(execId1, actionId, runId1, '2026-01-01T00:00:00.000Z');

      db.prepare(
        `INSERT INTO action_executions (id, action_id, run_id, executor, input_json, output_json, started_at)
         VALUES (?, ?, ?, 'exec-2', '{}', '{}', ?)`,
      ).run(execId2, actionId, runId1, '2026-01-02T00:00:00.000Z');

      // run 2 に 1 件作成
      repo.create({ actionId, runId: runId2, executor: 'other-executor' });

      const executions = repo.findByRun(runId1);

      expect(executions).toHaveLength(2);
      expect(executions.every((e: ActionExecution) => e.runId === runId1)).toBe(true);

      // started_at DESC 順：execId2 が先（より新しい）
      expect(executions[0].id).toBe(execId2);
      expect(executions[1].id).toBe(execId1);
    });
  });

  // =======================================================================
  // complete()
  // =======================================================================

  describe('complete()', () => {
    it('正常完了 — sets finished_at, duration_ms, outputJson, exitCode', () => {
      const exec = repo.create({
        actionId,
        executor: 'nmap-executor',
        command: 'nmap -sV 10.0.0.1',
      });

      const completed = repo.complete(exec.id, {
        outputJson: '{"hosts":[{"ip":"10.0.0.1","ports":[22,80]}]}',
        exitCode: 0,
      });

      expect(completed).toBeDefined();
      expect(completed!.id).toBe(exec.id);
      expect(completed!.outputJson).toBe('{"hosts":[{"ip":"10.0.0.1","ports":[22,80]}]}');
      expect(completed!.exitCode).toBe(0);
      expect(completed!.finishedAt).toBeDefined();
      expect(completed!.durationMs).toBeDefined();
      expect(typeof completed!.durationMs).toBe('number');
      expect(completed!.errorType).toBeUndefined();
      expect(completed!.errorMessage).toBeUndefined();
    });

    it('エラー完了 — sets errorType and errorMessage along with exitCode', () => {
      const exec = repo.create({
        actionId,
        executor: 'nmap-executor',
        command: 'nmap -sV 10.0.0.1',
      });

      const completed = repo.complete(exec.id, {
        exitCode: 1,
        errorType: 'TIMEOUT',
        errorMessage: 'Scan timed out after 300s',
      });

      expect(completed).toBeDefined();
      expect(completed!.exitCode).toBe(1);
      expect(completed!.errorType).toBe('TIMEOUT');
      expect(completed!.errorMessage).toBe('Scan timed out after 300s');
      expect(completed!.finishedAt).toBeDefined();
      expect(completed!.durationMs).toBeDefined();
    });

    it('duration_ms 自動計算 — duration_ms should be >= 0', () => {
      // started_at を明示的に過去の時刻で挿入して duration を検証
      const execId = crypto.randomUUID();
      const startedAt = '2025-01-01T00:00:00.000Z';

      db.prepare(
        `INSERT INTO action_executions (id, action_id, executor, input_json, output_json, started_at)
         VALUES (?, ?, 'test-executor', '{}', '{}', ?)`,
      ).run(execId, actionId, startedAt);

      const completed = repo.complete(execId, {
        outputJson: '{"result":"ok"}',
        exitCode: 0,
      });

      expect(completed).toBeDefined();
      expect(completed!.durationMs).toBeDefined();
      expect(completed!.durationMs!).toBeGreaterThanOrEqual(0);
      // duration_ms should match finishedAt - startedAt
      const expectedDuration =
        new Date(completed!.finishedAt!).getTime() - new Date(startedAt).getTime();
      expect(completed!.durationMs).toBe(expectedDuration);
    });

    it('存在しないID — returns undefined', () => {
      const result = repo.complete(crypto.randomUUID(), {
        outputJson: '{}',
        exitCode: 0,
      });
      expect(result).toBeUndefined();
    });
  });
});
