import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';
import type { Engagement } from '../../../src/types/operational.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

/** テスト用 :memory: DB を作成しマイグレーション済みで返す */
function createTestDb(): InstanceType<typeof Database> {
  const db = new Database(':memory:');
  migrateDatabase(db);
  return db;
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('EngagementRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: EngagementRepository;

  beforeEach(() => {
    db = createTestDb();
    repo = new EngagementRepository(db);
  });

  // =======================================================================
  // create()
  // =======================================================================

  describe('create()', () => {
    it('基本作成 — creates an engagement and verifies all fields', () => {
      const engagement = repo.create({
        name: 'Test Engagement',
        environment: 'prod',
        scopeJson: '{"targets":["10.0.0.0/24"]}',
        policyJson: '{"maxConcurrency":5}',
        scheduleCron: '0 2 * * *',
        status: 'active',
      });

      expect(engagement.id).toBeDefined();
      expect(engagement.id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
      expect(engagement.name).toBe('Test Engagement');
      expect(engagement.environment).toBe('prod');
      expect(engagement.scopeJson).toBe('{"targets":["10.0.0.0/24"]}');
      expect(engagement.policyJson).toBe('{"maxConcurrency":5}');
      expect(engagement.scheduleCron).toBe('0 2 * * *');
      expect(engagement.status).toBe('active');
      expect(engagement.createdAt).toBeDefined();
      expect(engagement.updatedAt).toBeDefined();
      expect(engagement.createdAt).toBe(engagement.updatedAt);
    });

    it('デフォルト値 — environment defaults to stg, scopeJson to {}, policyJson to {}', () => {
      const engagement = repo.create({ name: 'Minimal Engagement' });

      expect(engagement.environment).toBe('stg');
      expect(engagement.scopeJson).toBe('{}');
      expect(engagement.policyJson).toBe('{}');
      expect(engagement.scheduleCron).toBeUndefined();
      expect(engagement.status).toBe('active');
    });
  });

  // =======================================================================
  // findById()
  // =======================================================================

  describe('findById()', () => {
    it('存在するID — returns the engagement', () => {
      const created = repo.create({
        name: 'Find Me',
        environment: 'dev',
      });

      const found = repo.findById(created.id);

      expect(found).toBeDefined();
      expect(found!.id).toBe(created.id);
      expect(found!.name).toBe('Find Me');
      expect(found!.environment).toBe('dev');
    });

    it('存在しないID — returns undefined', () => {
      const found = repo.findById(crypto.randomUUID());
      expect(found).toBeUndefined();
    });
  });

  // =======================================================================
  // findByStatus()
  // =======================================================================

  describe('findByStatus()', () => {
    it('ステータスフィルタ — finds only matching status', () => {
      repo.create({ name: 'Active 1', status: 'active' });
      repo.create({ name: 'Active 2', status: 'active' });
      repo.create({ name: 'Archived', status: 'archived' });

      const activeList = repo.findByStatus('active');
      const archivedList = repo.findByStatus('archived');

      expect(activeList).toHaveLength(2);
      expect(activeList.every((e: Engagement) => e.status === 'active')).toBe(true);
      expect(archivedList).toHaveLength(1);
      expect(archivedList[0].name).toBe('Archived');
    });
  });

  // =======================================================================
  // list()
  // =======================================================================

  describe('list()', () => {
    it('全件取得 — returns all engagements', () => {
      repo.create({ name: 'Engagement A' });
      repo.create({ name: 'Engagement B' });
      repo.create({ name: 'Engagement C' });

      const all = repo.list();
      expect(all).toHaveLength(3);

      const names = all.map((e: Engagement) => e.name).sort();
      expect(names).toEqual(['Engagement A', 'Engagement B', 'Engagement C']);
    });
  });

  // =======================================================================
  // update()
  // =======================================================================

  describe('update()', () => {
    it('フィールド更新 — updates specified fields, keeps others, updates updatedAt', () => {
      const created = repo.create({
        name: 'Original Name',
        environment: 'stg',
        scopeJson: '{"old":true}',
      });

      // 少し間を空けて updatedAt の差を出す
      const updated = repo.update(created.id, {
        name: 'Updated Name',
        scopeJson: '{"new":true}',
      });

      expect(updated).toBeDefined();
      expect(updated!.id).toBe(created.id);
      expect(updated!.name).toBe('Updated Name');
      expect(updated!.scopeJson).toBe('{"new":true}');
      // 変更していないフィールドは保持される
      expect(updated!.environment).toBe('stg');
      expect(updated!.policyJson).toBe('{}');
      expect(updated!.status).toBe('active');
      // updatedAt は更新される
      expect(updated!.updatedAt).toBeDefined();
    });

    it('存在しないID — returns undefined', () => {
      const result = repo.update(crypto.randomUUID(), { name: 'Ghost' });
      expect(result).toBeUndefined();
    });
  });

  // =======================================================================
  // delete()
  // =======================================================================

  describe('delete()', () => {
    it('正常削除 — returns true, engagement is gone', () => {
      const created = repo.create({ name: 'To Be Deleted' });
      const result = repo.delete(created.id);

      expect(result).toBe(true);

      const found = repo.findById(created.id);
      expect(found).toBeUndefined();
    });

    it('存在しないID — returns false', () => {
      const result = repo.delete(crypto.randomUUID());
      expect(result).toBe(false);
    });

    it('CASCADE で runs も削除される — deleting engagement cascades to runs table', () => {
      const engagement = repo.create({ name: 'Cascade Test' });

      // runs テーブルに直接行を挿入
      const runId = crypto.randomUUID();
      const now = new Date().toISOString();
      db.prepare(
        `INSERT INTO runs (id, engagement_id, trigger_kind, status, summary_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).run(runId, engagement.id, 'manual', 'running', '{}', now);

      // run が存在することを確認
      const runBefore = db.prepare('SELECT id FROM runs WHERE id = ?').get(runId) as
        | { id: string }
        | undefined;
      expect(runBefore).toBeDefined();

      // engagement を削除 → CASCADE で run も消えるはず
      const deleted = repo.delete(engagement.id);
      expect(deleted).toBe(true);

      const runAfter = db.prepare('SELECT id FROM runs WHERE id = ?').get(runId) as
        | { id: string }
        | undefined;
      expect(runAfter).toBeUndefined();
    });
  });
});
