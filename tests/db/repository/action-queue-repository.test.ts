import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { ActionQueueRepository } from '../../../src/db/repository/action-queue-repository.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';
import type { ActionQueueItem } from '../../../src/types/operational.js';

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

describe('ActionQueueRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: ActionQueueRepository;
  let engagementRepo: EngagementRepository;
  let engagementId: string;

  beforeEach(() => {
    db = createTestDb();
    repo = new ActionQueueRepository(db);
    engagementRepo = new EngagementRepository(db);
    const engagement = engagementRepo.create({ name: 'Test Engagement' });
    engagementId = engagement.id;
  });

  // =======================================================================
  // enqueue()
  // =======================================================================

  describe('enqueue()', () => {
    it('基本作成 — creates an action with all fields and correct defaults', () => {
      const item = repo.enqueue({
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:10.0.0.0/24',
      });

      expect(item.id).toBeDefined();
      expect(item.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
      expect(item.engagementId).toBe(engagementId);
      expect(item.runId).toBeUndefined();
      expect(item.parentActionId).toBeUndefined();
      expect(item.kind).toBe('nmap_scan');
      expect(item.priority).toBe(100);
      expect(item.dedupeKey).toBe('nmap:10.0.0.0/24');
      expect(item.paramsJson).toBe('{}');
      expect(item.state).toBe('queued');
      expect(item.attemptCount).toBe(0);
      expect(item.maxAttempts).toBe(3);
      expect(item.availableAt).toBeDefined();
      expect(item.leaseOwner).toBeUndefined();
      expect(item.leaseExpiresAt).toBeUndefined();
      expect(item.lastError).toBeUndefined();
      expect(item.createdAt).toBeDefined();
      expect(item.updatedAt).toBeDefined();
      expect(item.createdAt).toBe(item.updatedAt);
    });

    it('dedupe_key重複（queued状態）で UNIQUE制約エラー', () => {
      repo.enqueue({
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:10.0.0.0/24',
      });

      expect(() =>
        repo.enqueue({
          engagementId,
          kind: 'nmap_scan',
          dedupeKey: 'nmap:10.0.0.0/24',
        }),
      ).toThrow();
    });

    it('succeeded後の同じdedupe_keyは成功', () => {
      const first = repo.enqueue({
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:10.0.0.0/24',
      });

      // poll して running にする
      repo.poll('worker-1');
      // complete して succeeded にする
      repo.complete(first.id);

      // 同じ dedupe_key で新しいアクションを作成できる
      const second = repo.enqueue({
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:10.0.0.0/24',
      });

      expect(second.id).toBeDefined();
      expect(second.id).not.toBe(first.id);
      expect(second.dedupeKey).toBe('nmap:10.0.0.0/24');
    });
  });

  // =======================================================================
  // findById()
  // =======================================================================

  describe('findById()', () => {
    it('存在するID — returns the item', () => {
      const created = repo.enqueue({
        engagementId,
        kind: 'nuclei_scan',
        dedupeKey: 'nuclei:example.com',
        priority: 50,
        paramsJson: '{"target":"example.com"}',
        maxAttempts: 5,
      });

      const found = repo.findById(created.id);

      expect(found).toBeDefined();
      expect(found!.id).toBe(created.id);
      expect(found!.engagementId).toBe(engagementId);
      expect(found!.kind).toBe('nuclei_scan');
      expect(found!.priority).toBe(50);
      expect(found!.dedupeKey).toBe('nuclei:example.com');
      expect(found!.paramsJson).toBe('{"target":"example.com"}');
      expect(found!.state).toBe('queued');
      expect(found!.maxAttempts).toBe(5);
    });

    it('存在しないID — returns undefined', () => {
      const found = repo.findById(crypto.randomUUID());
      expect(found).toBeUndefined();
    });
  });

  // =======================================================================
  // poll()
  // =======================================================================

  describe('poll()', () => {
    it('基本ポーリング — returns oldest queued item, sets state=running with lease', () => {
      const created = repo.enqueue({
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:10.0.0.1',
      });

      const polled = repo.poll('worker-1');

      expect(polled).toBeDefined();
      expect(polled!.id).toBe(created.id);
      expect(polled!.state).toBe('running');
      expect(polled!.leaseOwner).toBe('worker-1');
      expect(polled!.leaseExpiresAt).toBeDefined();
      expect(polled!.attemptCount).toBe(1);

      // DB にも反映されていることを確認
      const found = repo.findById(created.id);
      expect(found!.state).toBe('running');
      expect(found!.leaseOwner).toBe('worker-1');
    });

    it('キューが空 — returns undefined', () => {
      const polled = repo.poll('worker-1');
      expect(polled).toBeUndefined();
    });

    it('available_atが未来のアイテムはスキップ', () => {
      const futureDate = new Date(Date.now() + 3600 * 1000).toISOString();

      repo.enqueue({
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:future',
        availableAt: futureDate,
      });

      const polled = repo.poll('worker-1');
      expect(polled).toBeUndefined();
    });

    it('priority順 — lower priority number is polled first', () => {
      // priority の低い方が先にポーリングされる（priority=10 < priority=100）
      const lowPriority = repo.enqueue({
        engagementId,
        kind: 'critical_scan',
        dedupeKey: 'scan:critical',
        priority: 10,
      });

      repo.enqueue({
        engagementId,
        kind: 'normal_scan',
        dedupeKey: 'scan:normal',
        priority: 100,
      });

      const polled = repo.poll('worker-1');

      expect(polled).toBeDefined();
      expect(polled!.id).toBe(lowPriority.id);
      expect(polled!.kind).toBe('critical_scan');
    });
  });

  // =======================================================================
  // complete()
  // =======================================================================

  describe('complete()', () => {
    it('正常完了 — state→succeeded', () => {
      const item = repo.enqueue({
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:complete-test',
      });

      // poll して running にする
      repo.poll('worker-1');

      const result = repo.complete(item.id);
      expect(result).toBe(true);

      const found = repo.findById(item.id);
      expect(found!.state).toBe('succeeded');
      expect(found!.attemptCount).toBe(1);
    });

    it('存在しないID — returns false', () => {
      const result = repo.complete(crypto.randomUUID());
      expect(result).toBe(false);
    });
  });

  // =======================================================================
  // fail()
  // =======================================================================

  describe('fail()', () => {
    it('リトライ可能（attempt_count < maxAttempts） — state→queued with backoff', () => {
      const item = repo.enqueue({
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:retry-test',
        maxAttempts: 3,
      });

      // poll して running にする（attempt_count = 1）
      repo.poll('worker-1');

      const beforeFail = new Date();
      const result = repo.fail(item.id, 'connection timeout');
      expect(result).toBe(true);

      const found = repo.findById(item.id);
      expect(found!.state).toBe('queued');
      expect(found!.attemptCount).toBe(1);
      expect(found!.lastError).toBe('connection timeout');
      expect(found!.leaseOwner).toBeUndefined();
      expect(found!.leaseExpiresAt).toBeUndefined();

      // available_at がバックオフ付きで更新されていることを確認
      const availableAt = new Date(found!.availableAt);
      expect(availableAt.getTime()).toBeGreaterThanOrEqual(beforeFail.getTime());
    });

    it('dead letter（attempt_count >= maxAttempts） — state→failed', () => {
      const item = repo.enqueue({
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:dead-letter',
        maxAttempts: 1,
      });

      // poll して running にする（attempt_count = 1）
      repo.poll('worker-1');

      // attempt_count(1) >= maxAttempts(1) なので dead letter
      const result = repo.fail(item.id, 'permanent failure');
      expect(result).toBe(true);

      const found = repo.findById(item.id);
      expect(found!.state).toBe('failed');
      expect(found!.lastError).toBe('permanent failure');
    });
  });

  // =======================================================================
  // findByEngagement()
  // =======================================================================

  describe('findByEngagement()', () => {
    it('エンゲージメントフィルタ — returns items for engagement', () => {
      const engagement2 = engagementRepo.create({ name: 'Other Engagement' });

      repo.enqueue({
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:eng1-a',
      });
      repo.enqueue({
        engagementId,
        kind: 'nuclei_scan',
        dedupeKey: 'nuclei:eng1-b',
      });
      repo.enqueue({
        engagementId: engagement2.id,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:eng2-a',
      });

      const items = repo.findByEngagement(engagementId);

      expect(items).toHaveLength(2);
      expect(items.every((i: ActionQueueItem) => i.engagementId === engagementId)).toBe(true);
    });

    it('stateフィルタ — returns items filtered by state', () => {
      const item1 = repo.enqueue({
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:state-filter-a',
      });
      repo.enqueue({
        engagementId,
        kind: 'nuclei_scan',
        dedupeKey: 'nuclei:state-filter-b',
      });

      // item1 を running にする
      repo.poll('worker-1');

      const queuedItems = repo.findByEngagement(engagementId, 'queued');
      const runningItems = repo.findByEngagement(engagementId, 'running');

      expect(queuedItems).toHaveLength(1);
      expect(queuedItems[0].kind).toBe('nuclei_scan');

      expect(runningItems).toHaveLength(1);
      expect(runningItems[0].id).toBe(item1.id);
      expect(runningItems[0].state).toBe('running');
    });
  });

  // =======================================================================
  // cancel()
  // =======================================================================

  describe('cancel()', () => {
    it('正常キャンセル — state→cancelled', () => {
      const item = repo.enqueue({
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:cancel-test',
      });

      const result = repo.cancel(item.id);
      expect(result).toBe(true);

      const found = repo.findById(item.id);
      expect(found!.state).toBe('cancelled');
    });

    it('存在しないID — returns false', () => {
      const result = repo.cancel(crypto.randomUUID());
      expect(result).toBe(false);
    });
  });
});
