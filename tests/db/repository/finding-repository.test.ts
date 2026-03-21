import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { FindingRepository } from '../../../src/db/repository/finding-repository.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';
import { RunRepository } from '../../../src/db/repository/run-repository.js';
import type { Finding, FindingEvent } from '../../../src/types/operational.js';

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

describe('FindingRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: FindingRepository;
  let engagementRepo: EngagementRepository;
  let runRepo: RunRepository;
  let engagementId: string;
  let runId1: string;
  let runId2: string;

  beforeEach(() => {
    db = createTestDb();
    repo = new FindingRepository(db);
    engagementRepo = new EngagementRepository(db);
    runRepo = new RunRepository(db);

    // テスト用エンゲージメントを事前作成
    const engagement = engagementRepo.create({ name: 'Test Engagement' });
    engagementId = engagement.id;

    // テスト用 run を事前作成（外部キー制約を満たすため）
    const run1 = runRepo.create({
      engagementId,
      triggerKind: 'manual',
      status: 'running',
    });
    runId1 = run1.id;

    const run2 = runRepo.create({
      engagementId,
      triggerKind: 'manual',
      status: 'running',
    });
    runId2 = run2.id;
  });

  // =======================================================================
  // upsert()
  // =======================================================================

  describe('upsert()', () => {
    it('新規作成 — creates finding + finding_events has discovered event', () => {
      const result = repo.upsert({
        engagementId,
        canonicalKey: 'CVE-2024-1234:host:192.168.1.1',
        title: 'SQL Injection in login form',
        severity: 'critical',
        confidence: 'high',
        runId: runId1,
        attrsJson: '{"cve":"CVE-2024-1234"}',
      });

      // created フラグが true
      expect(result.created).toBe(true);

      // Finding の各フィールドを検証
      const finding = result.finding;
      expect(finding.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
      expect(finding.engagementId).toBe(engagementId);
      expect(finding.canonicalKey).toBe('CVE-2024-1234:host:192.168.1.1');
      expect(finding.title).toBe('SQL Injection in login form');
      expect(finding.severity).toBe('critical');
      expect(finding.confidence).toBe('high');
      expect(finding.state).toBe('open');
      expect(finding.firstSeenRunId).toBe(runId1);
      expect(finding.lastSeenRunId).toBe(runId1);
      expect(finding.firstSeenAt).toBeDefined();
      expect(finding.lastSeenAt).toBeDefined();
      expect(finding.firstSeenAt).toBe(finding.lastSeenAt);
      expect(finding.attrsJson).toBe('{"cve":"CVE-2024-1234"}');

      // discovered イベントが finding_events に存在する
      const events = repo.getEvents(finding.id);
      expect(events).toHaveLength(1);
      expect(events[0].eventType).toBe('discovered');
      expect(events[0].findingId).toBe(finding.id);
      expect(events[0].runId).toBe(runId1);
    });

    it('既存更新（re_observed） — same engagement+canonical_key: created=false, last_seen_at updated', () => {
      // 初回挿入
      const first = repo.upsert({
        engagementId,
        canonicalKey: 'CVE-2024-5678:host:10.0.0.1',
        title: 'XSS in search',
        severity: 'high',
        confidence: 'medium',
        runId: runId1,
      });
      expect(first.created).toBe(true);

      // 同じ engagement + canonical_key で再度 upsert
      const second = repo.upsert({
        engagementId,
        canonicalKey: 'CVE-2024-5678:host:10.0.0.1',
        title: 'XSS in search (updated)',
        severity: 'high',
        confidence: 'high',
        runId: runId2,
      });

      expect(second.created).toBe(false);
      expect(second.finding.id).toBe(first.finding.id);
      expect(second.finding.lastSeenRunId).toBe(runId2);
      expect(second.finding.title).toBe('XSS in search (updated)');
      expect(second.finding.confidence).toBe('high');
      // firstSeenRunId は変わらない
      expect(second.finding.firstSeenRunId).toBe(runId1);

      // finding_events に 'discovered' と 're_observed' の2件がある
      const events = repo.getEvents(first.finding.id);
      expect(events).toHaveLength(2);
      const eventTypes = events.map((e) => e.eventType).sort();
      expect(eventTypes).toEqual(['discovered', 're_observed']);
      // re_observed イベントには runId2 が設定されている
      const reObservedEvent = events.find((e) => e.eventType === 're_observed');
      expect(reObservedEvent?.runId).toBe(runId2);
    });

    it('異なるengagementでの同じcanonical_key — should create separate findings', () => {
      // 別のエンゲージメントを作成
      const engagement2 = engagementRepo.create({ name: 'Second Engagement' });

      const result1 = repo.upsert({
        engagementId,
        canonicalKey: 'CVE-2024-9999:host:172.16.0.1',
        title: 'SSRF in API',
        severity: 'critical',
        confidence: 'high',
      });

      const result2 = repo.upsert({
        engagementId: engagement2.id,
        canonicalKey: 'CVE-2024-9999:host:172.16.0.1',
        title: 'SSRF in API',
        severity: 'critical',
        confidence: 'high',
      });

      // 両方とも新規作成
      expect(result1.created).toBe(true);
      expect(result2.created).toBe(true);

      // 異なる Finding ID
      expect(result1.finding.id).not.toBe(result2.finding.id);

      // 各エンゲージメントに1件ずつ
      expect(result1.finding.engagementId).toBe(engagementId);
      expect(result2.finding.engagementId).toBe(engagement2.id);
    });
  });

  // =======================================================================
  // findById()
  // =======================================================================

  describe('findById()', () => {
    it('存在するID — returns finding', () => {
      const { finding: created } = repo.upsert({
        engagementId,
        canonicalKey: 'test:findById',
        title: 'Find Me',
        severity: 'medium',
        confidence: 'low',
      });

      const found = repo.findById(created.id);

      expect(found).toBeDefined();
      expect(found!.id).toBe(created.id);
      expect(found!.title).toBe('Find Me');
      expect(found!.severity).toBe('medium');
      expect(found!.confidence).toBe('low');
      expect(found!.engagementId).toBe(engagementId);
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
    it('エンゲージメントフィルタ — returns all findings for engagement', () => {
      repo.upsert({
        engagementId,
        canonicalKey: 'finding-1',
        title: 'Finding 1',
        severity: 'high',
        confidence: 'high',
      });
      repo.upsert({
        engagementId,
        canonicalKey: 'finding-2',
        title: 'Finding 2',
        severity: 'medium',
        confidence: 'medium',
      });

      // 別エンゲージメントに Finding を作成（混入しないことを確認）
      const engagement2 = engagementRepo.create({ name: 'Other' });
      repo.upsert({
        engagementId: engagement2.id,
        canonicalKey: 'finding-3',
        title: 'Finding 3',
        severity: 'low',
        confidence: 'low',
      });

      const findings = repo.findByEngagement(engagementId);
      expect(findings).toHaveLength(2);
      expect(findings.every((f: Finding) => f.engagementId === engagementId)).toBe(true);
    });

    it('stateフィルタ — filters by state', () => {
      repo.upsert({
        engagementId,
        canonicalKey: 'state-open',
        title: 'Open Finding',
        severity: 'high',
        confidence: 'high',
      });
      repo.upsert({
        engagementId,
        canonicalKey: 'state-closed',
        title: 'Closed Finding',
        severity: 'medium',
        confidence: 'medium',
      });

      // 2つ目を closed に変更
      const allFindings = repo.findByEngagement(engagementId);
      const closedFinding = allFindings.find((f: Finding) => f.canonicalKey === 'state-closed')!;
      repo.updateState(closedFinding.id, 'closed', 'Fixed');

      const openFindings = repo.findByEngagement(engagementId, { state: 'open' });
      expect(openFindings).toHaveLength(1);
      expect(openFindings[0].canonicalKey).toBe('state-open');

      const closedFindings = repo.findByEngagement(engagementId, { state: 'closed' });
      expect(closedFindings).toHaveLength(1);
      expect(closedFindings[0].canonicalKey).toBe('state-closed');
    });

    it('severityフィルタ — filters by severity', () => {
      repo.upsert({
        engagementId,
        canonicalKey: 'sev-critical',
        title: 'Critical Finding',
        severity: 'critical',
        confidence: 'high',
      });
      repo.upsert({
        engagementId,
        canonicalKey: 'sev-low',
        title: 'Low Finding',
        severity: 'low',
        confidence: 'low',
      });

      const criticalFindings = repo.findByEngagement(engagementId, { severity: 'critical' });
      expect(criticalFindings).toHaveLength(1);
      expect(criticalFindings[0].severity).toBe('critical');

      const lowFindings = repo.findByEngagement(engagementId, { severity: 'low' });
      expect(lowFindings).toHaveLength(1);
      expect(lowFindings[0].severity).toBe('low');
    });
  });

  // =======================================================================
  // updateState()
  // =======================================================================

  describe('updateState()', () => {
    it('状態更新 — updates state, state_reason. Auto-creates state_change event', () => {
      const { finding } = repo.upsert({
        engagementId,
        canonicalKey: 'state-change-test',
        title: 'State Change Target',
        severity: 'high',
        confidence: 'high',
      });

      expect(finding.state).toBe('open');

      const updated = repo.updateState(finding.id, 'closed', 'Verified as false positive');

      expect(updated).toBeDefined();
      expect(updated!.state).toBe('closed');
      expect(updated!.stateReason).toBe('Verified as false positive');

      // state_change イベントが追加されている
      const events = repo.getEvents(finding.id);
      // discovered + state_change = 2件
      const stateChangeEvents = events.filter((e: FindingEvent) => e.eventType === 'state_change');
      expect(stateChangeEvents).toHaveLength(1);
      expect(JSON.parse(stateChangeEvents[0].beforeJson)).toEqual({ state: 'open' });
      expect(JSON.parse(stateChangeEvents[0].afterJson)).toEqual({ state: 'closed' });
    });

    it('存在しないID — returns undefined', () => {
      const result = repo.updateState(crypto.randomUUID(), 'closed', 'No reason');
      expect(result).toBeUndefined();
    });
  });

  // =======================================================================
  // addEvent()
  // =======================================================================

  describe('addEvent()', () => {
    it('イベント追加 — manually adds finding_event', () => {
      const { finding } = repo.upsert({
        engagementId,
        canonicalKey: 'event-test',
        title: 'Event Test',
        severity: 'medium',
        confidence: 'medium',
      });

      const event = repo.addEvent(finding.id, {
        eventType: 'manual_review',
        runId: runId1,
        beforeJson: '{"state":"open"}',
        afterJson: '{"state":"reviewed"}',
      });

      expect(event.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
      expect(event.findingId).toBe(finding.id);
      expect(event.eventType).toBe('manual_review');
      expect(event.runId).toBe(runId1);
      expect(event.beforeJson).toBe('{"state":"open"}');
      expect(event.afterJson).toBe('{"state":"reviewed"}');
      expect(event.createdAt).toBeDefined();
    });
  });

  // =======================================================================
  // getEvents()
  // =======================================================================

  describe('getEvents()', () => {
    it('イベント一覧 — returns events ordered by created_at DESC', () => {
      const { finding } = repo.upsert({
        engagementId,
        canonicalKey: 'events-list-test',
        title: 'Events List Test',
        severity: 'low',
        confidence: 'low',
      });

      // 追加イベントを挿入
      repo.addEvent(finding.id, {
        eventType: 'escalated',
        beforeJson: '{"priority":"low"}',
        afterJson: '{"priority":"high"}',
      });
      repo.addEvent(finding.id, {
        eventType: 'assigned',
        afterJson: '{"owner":"analyst-1"}',
      });

      const events = repo.getEvents(finding.id);

      // discovered + escalated + assigned = 3件
      expect(events).toHaveLength(3);

      // created_at DESC 順であること（最新が先頭）
      for (let i = 0; i < events.length - 1; i++) {
        expect(events[i].createdAt >= events[i + 1].createdAt).toBe(true);
      }
    });
  });

  // =======================================================================
  // delete()
  // =======================================================================

  describe('delete()', () => {
    it('正常削除 — finding + cascaded events deleted', () => {
      const { finding } = repo.upsert({
        engagementId,
        canonicalKey: 'delete-test',
        title: 'To Be Deleted',
        severity: 'info',
        confidence: 'low',
      });

      // イベントも追加
      repo.addEvent(finding.id, {
        eventType: 'manual_note',
        afterJson: '{"note":"test"}',
      });

      // 削除前にイベントが存在することを確認
      expect(repo.getEvents(finding.id)).toHaveLength(2); // discovered + manual_note

      const result = repo.delete(finding.id);
      expect(result).toBe(true);

      // Finding が取得できない
      expect(repo.findById(finding.id)).toBeUndefined();

      // CASCADE により finding_events も削除されている
      const eventsAfter = db
        .prepare('SELECT id FROM finding_events WHERE finding_id = ?')
        .all(finding.id);
      expect(eventsAfter).toHaveLength(0);
    });

    it('存在しないID — returns false', () => {
      const result = repo.delete(crypto.randomUUID());
      expect(result).toBe(false);
    });
  });
});
