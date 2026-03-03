import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { RunRepository } from '../../../src/db/repository/run-repository.js';
import type { Run } from '../../../src/types/operational.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

/** テスト用 :memory: DB を作成しマイグレーション済みで返す */
function createTestDb(): InstanceType<typeof Database> {
  const db = new Database(':memory:');
  migrateDatabase(db);
  return db;
}

/** テスト用 engagement レコードを挿入し id を返す */
function insertTestEngagement(db: InstanceType<typeof Database>, name?: string): string {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO engagements (id, name, environment, scope_json, policy_json, status, created_at, updated_at)
     VALUES (?, ?, 'stg', '{}', '{}', 'active', ?, ?)`,
  ).run(id, name ?? 'Test Engagement', now, now);
  return id;
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('RunRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: RunRepository;
  let engagementId: string;

  beforeEach(() => {
    db = createTestDb();
    repo = new RunRepository(db);
    engagementId = insertTestEngagement(db);
  });

  // =======================================================================
  // create()
  // =======================================================================

  describe('create()', () => {
    it('基本作成 — creates a run with all fields verified', () => {
      const run = repo.create({
        engagementId,
        triggerKind: 'manual',
        triggerRef: 'user:admin',
        status: 'running',
      });

      expect(run.id).toBeDefined();
      expect(run.id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
      expect(run.engagementId).toBe(engagementId);
      expect(run.triggerKind).toBe('manual');
      expect(run.triggerRef).toBe('user:admin');
      expect(run.status).toBe('running');
      expect(run.startedAt).toBeDefined();
      expect(run.summaryJson).toBe('{}');
      expect(run.createdAt).toBeDefined();
    });

    it('デフォルト値 — summaryJson defaults to {}, started_at/finished_at null when pending', () => {
      const run = repo.create({
        engagementId,
        triggerKind: 'scheduled',
        status: 'pending',
      });

      expect(run.summaryJson).toBe('{}');
      expect(run.startedAt).toBeUndefined();
      expect(run.finishedAt).toBeUndefined();
      expect(run.triggerRef).toBeUndefined();
    });
  });

  // =======================================================================
  // findById()
  // =======================================================================

  describe('findById()', () => {
    it('存在するID — returns the run', () => {
      const created = repo.create({
        engagementId,
        triggerKind: 'manual',
        status: 'running',
      });

      const found = repo.findById(created.id);

      expect(found).toBeDefined();
      expect(found!.id).toBe(created.id);
      expect(found!.engagementId).toBe(engagementId);
      expect(found!.triggerKind).toBe('manual');
      expect(found!.status).toBe('running');
      expect(found!.startedAt).toBeDefined();
      expect(found!.summaryJson).toBe('{}');
      expect(found!.createdAt).toBeDefined();
    });

    it('存在しないID — returns undefined', () => {
      const found = repo.findById(crypto.randomUUID());
      expect(found).toBeUndefined();
    });
  });

  // =======================================================================
  // findByEngagement()
  // =======================================================================

  describe('findByEngagement()', () => {
    it('エンゲージメントフィルタ — returns only runs for given engagement, ordered by created_at DESC', () => {
      const engagementId2 = insertTestEngagement(db, 'Other Engagement');

      // engagement 1 に 2 件作成（created_at に明確な時間差を設ける）
      const runId1 = crypto.randomUUID();
      const runId2 = crypto.randomUUID();

      db.prepare(
        `INSERT INTO runs (id, engagement_id, trigger_kind, status, summary_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).run(runId1, engagementId, 'manual', 'pending', '{}', '2026-01-01T00:00:00.000Z');

      db.prepare(
        `INSERT INTO runs (id, engagement_id, trigger_kind, status, summary_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).run(runId2, engagementId, 'scheduled', 'running', '{}', '2026-01-02T00:00:00.000Z');

      // engagement 2 に 1 件作成
      repo.create({
        engagementId: engagementId2,
        triggerKind: 'manual',
        status: 'pending',
      });

      const runs = repo.findByEngagement(engagementId);

      expect(runs).toHaveLength(2);
      expect(runs.every((r: Run) => r.engagementId === engagementId)).toBe(true);

      // created_at DESC 順：runId2 が先（より新しい）
      expect(runs[0].id).toBe(runId2);
      expect(runs[1].id).toBe(runId1);
    });

    it('limit指定 — respects the limit parameter', () => {
      // 5 件作成
      for (let i = 0; i < 5; i++) {
        repo.create({
          engagementId,
          triggerKind: 'manual',
          status: 'pending',
        });
      }

      const limited = repo.findByEngagement(engagementId, 3);
      expect(limited).toHaveLength(3);

      const all = repo.findByEngagement(engagementId);
      expect(all).toHaveLength(5);
    });
  });

  // =======================================================================
  // findByStatus()
  // =======================================================================

  describe('findByStatus()', () => {
    it('ステータスフィルタ — finds only matching status', () => {
      repo.create({ engagementId, triggerKind: 'manual', status: 'running' });
      repo.create({ engagementId, triggerKind: 'manual', status: 'running' });
      repo.create({ engagementId, triggerKind: 'manual', status: 'pending' });
      repo.create({ engagementId, triggerKind: 'scheduled', status: 'succeeded' });

      const running = repo.findByStatus('running');
      const pending = repo.findByStatus('pending');
      const succeeded = repo.findByStatus('succeeded');

      expect(running).toHaveLength(2);
      expect(running.every((r: Run) => r.status === 'running')).toBe(true);
      expect(pending).toHaveLength(1);
      expect(succeeded).toHaveLength(1);
    });
  });

  // =======================================================================
  // updateStatus()
  // =======================================================================

  describe('updateStatus()', () => {
    it('running → succeeded — updates status, auto-sets finished_at', () => {
      const run = repo.create({
        engagementId,
        triggerKind: 'manual',
        status: 'running',
      });

      const updated = repo.updateStatus(run.id, 'succeeded');

      expect(updated).toBeDefined();
      expect(updated!.status).toBe('succeeded');
      expect(updated!.finishedAt).toBeDefined();
    });

    it('running → failed — updates status, auto-sets finished_at', () => {
      const run = repo.create({
        engagementId,
        triggerKind: 'manual',
        status: 'running',
      });

      const updated = repo.updateStatus(run.id, 'failed');

      expect(updated).toBeDefined();
      expect(updated!.status).toBe('failed');
      expect(updated!.finishedAt).toBeDefined();
    });

    it('pending → running — does NOT set finished_at', () => {
      const run = repo.create({
        engagementId,
        triggerKind: 'manual',
        status: 'pending',
      });

      expect(run.startedAt).toBeUndefined();

      const updated = repo.updateStatus(run.id, 'running');

      expect(updated).toBeDefined();
      expect(updated!.status).toBe('running');
      expect(updated!.startedAt).toBeDefined();
      expect(updated!.finishedAt).toBeUndefined();
    });

    it('summaryJson更新 — optionally updates summaryJson', () => {
      const run = repo.create({
        engagementId,
        triggerKind: 'manual',
        status: 'running',
      });

      const summary = '{"hosts_scanned":42,"vulns_found":7}';
      const updated = repo.updateStatus(run.id, 'succeeded', summary);

      expect(updated).toBeDefined();
      expect(updated!.summaryJson).toBe(summary);
      expect(updated!.status).toBe('succeeded');
    });

    it('存在しないID — returns undefined', () => {
      const result = repo.updateStatus(crypto.randomUUID(), 'succeeded');
      expect(result).toBeUndefined();
    });
  });

  // =======================================================================
  // delete()
  // =======================================================================

  describe('delete()', () => {
    it('正常削除 — returns true, run is gone', () => {
      const created = repo.create({
        engagementId,
        triggerKind: 'manual',
        status: 'running',
      });

      const result = repo.delete(created.id);
      expect(result).toBe(true);

      const found = repo.findById(created.id);
      expect(found).toBeUndefined();
    });

    it('存在しないID — returns false', () => {
      const result = repo.delete(crypto.randomUUID());
      expect(result).toBe(false);
    });
  });
});
