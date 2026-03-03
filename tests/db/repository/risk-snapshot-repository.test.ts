import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { RiskSnapshotRepository } from '../../../src/db/repository/risk-snapshot-repository.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';
import { RunRepository } from '../../../src/db/repository/run-repository.js';
import type { RiskSnapshot } from '../../../src/types/operational.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

/** テスト用 :memory: DB を作成しマイグレーション済みで返す */
function createTestDb(): InstanceType<typeof Database> {
  const db = new Database(':memory:');
  migrateDatabase(db);
  return db;
}

/** created_at を制御するためにスリープする小さなヘルパー */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('RiskSnapshotRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: RiskSnapshotRepository;
  let engagementRepo: EngagementRepository;
  let runRepo: RunRepository;
  let engagementId: string;

  beforeEach(() => {
    db = createTestDb();
    repo = new RiskSnapshotRepository(db);
    engagementRepo = new EngagementRepository(db);
    runRepo = new RunRepository(db);

    // 全テストで使う共通エンゲージメントを作成
    const engagement = engagementRepo.create({ name: 'Test Engagement' });
    engagementId = engagement.id;
  });

  // =======================================================================
  // create()
  // =======================================================================

  describe('create()', () => {
    it('基本作成 — creates snapshot with all fields verified', () => {
      // run_id の FK 制約を満たすために実際の Run を作成
      const run = runRepo.create({
        engagementId,
        triggerKind: 'manual',
        status: 'running',
      });

      const snapshot = repo.create({
        engagementId,
        runId: run.id,
        score: 85.5,
        openCritical: 2,
        openHigh: 5,
        openMedium: 10,
        openLow: 20,
        openInfo: 3,
        openTotal: 40,
        attackPathCount: 7,
        exposedCredCount: 1,
        modelVersion: 'v1.0',
        attrsJson: '{"custom":"data"}',
      });

      // ID は UUID 形式
      expect(snapshot.id).toBeDefined();
      expect(snapshot.id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );

      // 全フィールドの検証
      expect(snapshot.engagementId).toBe(engagementId);
      expect(snapshot.runId).toBeDefined();
      expect(snapshot.score).toBe(85.5);
      expect(snapshot.openCritical).toBe(2);
      expect(snapshot.openHigh).toBe(5);
      expect(snapshot.openMedium).toBe(10);
      expect(snapshot.openLow).toBe(20);
      expect(snapshot.openInfo).toBe(3);
      expect(snapshot.openTotal).toBe(40);
      expect(snapshot.attackPathCount).toBe(7);
      expect(snapshot.exposedCredCount).toBe(1);
      expect(snapshot.modelVersion).toBe('v1.0');
      expect(snapshot.attrsJson).toBe('{"custom":"data"}');
      expect(snapshot.createdAt).toBeDefined();

      // DB に実際に保存されていることを確認
      const found = repo.findById(snapshot.id);
      expect(found).toBeDefined();
      expect(found!.score).toBe(85.5);
    });

    it('デフォルト値 — integer fields default to 0, attrsJson to \'{}\'', () => {
      const snapshot = repo.create({
        engagementId,
        score: 50.0,
      });

      expect(snapshot.openCritical).toBe(0);
      expect(snapshot.openHigh).toBe(0);
      expect(snapshot.openMedium).toBe(0);
      expect(snapshot.openLow).toBe(0);
      expect(snapshot.openInfo).toBe(0);
      expect(snapshot.openTotal).toBe(0);
      expect(snapshot.attackPathCount).toBe(0);
      expect(snapshot.exposedCredCount).toBe(0);
      expect(snapshot.modelVersion).toBeUndefined();
      expect(snapshot.runId).toBeUndefined();
      expect(snapshot.attrsJson).toBe('{}');
    });
  });

  // =======================================================================
  // findById()
  // =======================================================================

  describe('findById()', () => {
    it('存在するID — returns the snapshot', () => {
      const created = repo.create({
        engagementId,
        score: 72.3,
        openCritical: 1,
        openHigh: 3,
        modelVersion: 'v2.0',
      });

      const found = repo.findById(created.id);

      expect(found).toBeDefined();
      expect(found!.id).toBe(created.id);
      expect(found!.engagementId).toBe(engagementId);
      expect(found!.score).toBe(72.3);
      expect(found!.openCritical).toBe(1);
      expect(found!.openHigh).toBe(3);
      expect(found!.modelVersion).toBe('v2.0');
      expect(found!.createdAt).toBe(created.createdAt);
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
    it('エンゲージメントフィルタ — returns snapshots ordered by created_at DESC', async () => {
      // created_at の順序を保証するために明示的にタイムスタンプをずらして挿入
      const snap1 = repo.create({ engagementId, score: 10.0 });
      await delay(10);
      const snap2 = repo.create({ engagementId, score: 20.0 });
      await delay(10);
      const snap3 = repo.create({ engagementId, score: 30.0 });

      // 別のエンゲージメントにもスナップショットを追加（フィルタ確認用）
      const otherEngagement = engagementRepo.create({ name: 'Other Engagement' });
      repo.create({ engagementId: otherEngagement.id, score: 99.0 });

      const snapshots = repo.findByEngagement(engagementId);

      // 対象エンゲージメントのスナップショットのみ
      expect(snapshots).toHaveLength(3);

      // created_at DESC 順
      expect(snapshots[0].id).toBe(snap3.id);
      expect(snapshots[1].id).toBe(snap2.id);
      expect(snapshots[2].id).toBe(snap1.id);

      // 全て対象エンゲージメントのもの
      expect(snapshots.every((s: RiskSnapshot) => s.engagementId === engagementId)).toBe(true);
    });

    it('limit指定 — respects limit', async () => {
      repo.create({ engagementId, score: 10.0 });
      await delay(10);
      repo.create({ engagementId, score: 20.0 });
      await delay(10);
      const snap3 = repo.create({ engagementId, score: 30.0 });
      await delay(10);
      const snap4 = repo.create({ engagementId, score: 40.0 });

      const snapshots = repo.findByEngagement(engagementId, 2);

      expect(snapshots).toHaveLength(2);
      // 最新の2件（created_at DESC）
      expect(snapshots[0].id).toBe(snap4.id);
      expect(snapshots[1].id).toBe(snap3.id);
    });
  });

  // =======================================================================
  // latest()
  // =======================================================================

  describe('latest()', () => {
    it('最新スナップショット取得 — returns the most recent snapshot for engagement', async () => {
      repo.create({ engagementId, score: 10.0 });
      await delay(10);
      repo.create({ engagementId, score: 20.0 });
      await delay(10);
      const newest = repo.create({ engagementId, score: 30.0 });

      const latest = repo.latest(engagementId);

      expect(latest).toBeDefined();
      expect(latest!.id).toBe(newest.id);
      expect(latest!.score).toBe(30.0);
    });

    it('スナップショットなし — returns undefined when no snapshots exist', () => {
      const latest = repo.latest(engagementId);
      expect(latest).toBeUndefined();
    });
  });
});
