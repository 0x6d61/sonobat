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

/**
 * created_at を明示的に指定してスナップショットを直接挿入する。
 * delay() によるフレーキーテストを回避するため。
 */
function insertSnapshotWithTimestamp(
  db: InstanceType<typeof Database>,
  engagementId: string,
  score: number,
  createdAt: string,
): string {
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO risk_snapshots
       (id, engagement_id, score, open_critical, open_high, open_medium,
        open_low, open_info, open_total, attack_path_count, exposed_cred_count,
        attrs_json, created_at)
     VALUES (?, ?, ?, 0, 0, 0, 0, 0, 0, 0, 0, '{}', ?)`,
  ).run(id, engagementId, score, createdAt);
  return id;
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

    it("デフォルト値 — integer fields default to 0, attrsJson to '{}'", () => {
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
    it('エンゲージメントフィルタ — returns snapshots ordered by created_at DESC', () => {
      // 明示的なタイムスタンプで挿入（フレーキーテスト防止）
      const id1 = insertSnapshotWithTimestamp(db, engagementId, 10.0, '2026-01-01T00:00:00.000Z');
      const id2 = insertSnapshotWithTimestamp(db, engagementId, 20.0, '2026-01-02T00:00:00.000Z');
      const id3 = insertSnapshotWithTimestamp(db, engagementId, 30.0, '2026-01-03T00:00:00.000Z');

      // 別のエンゲージメントにもスナップショットを追加（フィルタ確認用）
      const otherEngagement = engagementRepo.create({ name: 'Other Engagement' });
      insertSnapshotWithTimestamp(db, otherEngagement.id, 99.0, '2026-01-04T00:00:00.000Z');

      const snapshots = repo.findByEngagement(engagementId);

      // 対象エンゲージメントのスナップショットのみ
      expect(snapshots).toHaveLength(3);

      // created_at DESC 順
      expect(snapshots[0].id).toBe(id3);
      expect(snapshots[1].id).toBe(id2);
      expect(snapshots[2].id).toBe(id1);

      // 全て対象エンゲージメントのもの
      expect(snapshots.every((s: RiskSnapshot) => s.engagementId === engagementId)).toBe(true);
    });

    it('limit指定 — respects limit', () => {
      insertSnapshotWithTimestamp(db, engagementId, 10.0, '2026-01-01T00:00:00.000Z');
      insertSnapshotWithTimestamp(db, engagementId, 20.0, '2026-01-02T00:00:00.000Z');
      const id3 = insertSnapshotWithTimestamp(db, engagementId, 30.0, '2026-01-03T00:00:00.000Z');
      const id4 = insertSnapshotWithTimestamp(db, engagementId, 40.0, '2026-01-04T00:00:00.000Z');

      const snapshots = repo.findByEngagement(engagementId, 2);

      expect(snapshots).toHaveLength(2);
      // 最新の2件（created_at DESC）
      expect(snapshots[0].id).toBe(id4);
      expect(snapshots[1].id).toBe(id3);
    });
  });

  // =======================================================================
  // latest()
  // =======================================================================

  describe('latest()', () => {
    it('最新スナップショット取得 — returns the most recent snapshot for engagement', () => {
      insertSnapshotWithTimestamp(db, engagementId, 10.0, '2026-01-01T00:00:00.000Z');
      insertSnapshotWithTimestamp(db, engagementId, 20.0, '2026-01-02T00:00:00.000Z');
      const newestId = insertSnapshotWithTimestamp(
        db,
        engagementId,
        30.0,
        '2026-01-03T00:00:00.000Z',
      );

      const latest = repo.latest(engagementId);

      expect(latest).toBeDefined();
      expect(latest!.id).toBe(newestId);
      expect(latest!.score).toBe(30.0);
    });

    it('スナップショットなし — returns undefined when no snapshots exist', () => {
      const latest = repo.latest(engagementId);
      expect(latest).toBeUndefined();
    });
  });
});
