/**
 * sonobat — MCP Findings Tool テスト
 *
 * InMemoryTransport で MCP サーバーとクライアントをインメモリ接続し、
 * findings ツールの全 9 アクションを検証する。
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { registerFindingsTools } from '../../../src/mcp/tools/findings.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

type TextContent = Array<{ type: string; text: string }>;

/** MCP ツール呼び出し結果からテキストをパースして返す */
function parseResponse<T>(result: { content: unknown }): T {
  const content = result.content as TextContent;
  return JSON.parse(content[0].text) as T;
}

/** MCP ツール呼び出し結果からテキストを返す */
function getText(result: { content: unknown }): string {
  const content = result.content as TextContent;
  return content[0].text;
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('MCP Findings Tool', () => {
  let db: InstanceType<typeof Database>;
  let client: Client;
  let engagementId: string;

  beforeEach(async () => {
    db = new Database(':memory:');
    migrateDatabase(db);

    // FK 制約のために engagement を作成
    const engagementRepo = new EngagementRepository(db);
    const engagement = engagementRepo.create({ name: 'Findings Test' });
    engagementId = engagement.id;

    const server = new McpServer({ name: 'test', version: '0.0.0' });
    registerFindingsTools(server, db);

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);

    client = new Client({ name: 'test-client', version: '0.0.0' });
    await client.connect(clientTransport);
  });

  afterEach(async () => {
    await client.close();
  });

  /** findings ツールを呼び出すヘルパー */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- MCP SDK callTool returns a complex union type
  async function callTool(args: Record<string, unknown>): Promise<any> {
    return await client.callTool({ name: 'findings', arguments: args });
  }

  // =========================================================
  // Finding アクション
  // =========================================================

  describe('Finding', () => {
    it('upsert_finding — 新規作成', async () => {
      const result = await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'sqli:login-form',
        title: 'SQL Injection in Login Form',
        severity: 'critical',
        confidence: 'high',
      });
      const data = parseResponse<{
        id: string;
        canonicalKey: string;
        title: string;
        severity: string;
        confidence: string;
        created: boolean;
      }>(result);
      expect(data.created).toBe(true);
      expect(data.id).toBeDefined();
      expect(data.canonicalKey).toBe('sqli:login-form');
      expect(data.title).toBe('SQL Injection in Login Form');
      expect(data.severity).toBe('critical');
      expect(data.confidence).toBe('high');
    });

    it('upsert_finding — 既存更新', async () => {
      // 1回目: 新規作成
      const firstResult = await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'xss:search',
        title: 'XSS in Search',
        severity: 'high',
        confidence: 'medium',
      });
      const first = parseResponse<{ id: string; created: boolean }>(firstResult);
      expect(first.created).toBe(true);

      // 2回目: 同じ canonical_key で更新
      const secondResult = await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'xss:search',
        title: 'XSS in Search (updated)',
        severity: 'critical',
        confidence: 'high',
      });
      const second = parseResponse<{
        id: string;
        created: boolean;
        title: string;
        severity: string;
      }>(secondResult);
      expect(second.created).toBe(false);
      expect(second.id).toBe(first.id);
    });

    it('get_finding — 存在するID', async () => {
      // 事前に finding を作成
      const createResult = await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'idor:user-api',
        title: 'IDOR in User API',
        severity: 'high',
        confidence: 'high',
      });
      const { id } = parseResponse<{ id: string }>(createResult);

      // get_finding
      const getResult = await callTool({ action: 'get_finding', id });
      const finding = parseResponse<{ id: string; title: string; canonicalKey: string }>(
        getResult,
      );
      expect(finding.id).toBe(id);
      expect(finding.title).toBe('IDOR in User API');
      expect(finding.canonicalKey).toBe('idor:user-api');
    });

    it('get_finding — 存在しないID', async () => {
      const result = await callTool({
        action: 'get_finding',
        id: '00000000-0000-0000-0000-000000000000',
      });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('not found');
    });

    it('list_findings — エンゲージメントフィルタ', async () => {
      // finding を2つ作成
      await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'sqli:login',
        title: 'SQLi Login',
        severity: 'critical',
        confidence: 'high',
      });
      await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'xss:comment',
        title: 'XSS Comment',
        severity: 'medium',
        confidence: 'medium',
      });

      const result = await callTool({
        action: 'list_findings',
        engagementId,
      });
      const findings = parseResponse<Array<{ id: string }>>(result);
      expect(findings).toHaveLength(2);
    });

    it('list_findings — stateフィルタ', async () => {
      // finding を作成（デフォルト state は open と想定）
      await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'sqli:search',
        title: 'SQLi Search',
        severity: 'high',
        confidence: 'high',
      });
      await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'info:leak',
        title: 'Info Leak',
        severity: 'low',
        confidence: 'medium',
        state: 'resolved',
      });

      const result = await callTool({
        action: 'list_findings',
        engagementId,
        state: 'open',
      });
      const findings = parseResponse<Array<{ canonicalKey: string }>>(result);
      expect(findings).toHaveLength(1);
      expect(findings[0].canonicalKey).toBe('sqli:search');
    });

    it('update_finding_state — 状態更新', async () => {
      // finding を作成
      const createResult = await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'ssrf:internal',
        title: 'SSRF to Internal',
        severity: 'critical',
        confidence: 'high',
      });
      const { id } = parseResponse<{ id: string }>(createResult);

      // 状態を更新
      const updateResult = await callTool({
        action: 'update_finding_state',
        id,
        state: 'resolved',
        stateReason: 'Patched in v2.1.0',
      });
      const updated = parseResponse<{ state: string; stateReason: string }>(updateResult);
      expect(updated.state).toBe('resolved');
      expect(updated.stateReason).toBe('Patched in v2.1.0');
    });

    it('list_finding_events — イベント一覧', async () => {
      // finding を作成 (upsert で自動的にイベントが記録される想定)
      const createResult = await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'rce:upload',
        title: 'RCE via File Upload',
        severity: 'critical',
        confidence: 'high',
      });
      const { id } = parseResponse<{ id: string }>(createResult);

      const eventsResult = await callTool({
        action: 'list_finding_events',
        findingId: id,
      });
      const events = parseResponse<Array<{ id: string; eventType: string }>>(eventsResult);
      // upsert (created) should produce at least one event
      expect(events.length).toBeGreaterThanOrEqual(1);
    });
  });

  // =========================================================
  // RiskSnapshot アクション
  // =========================================================

  describe('RiskSnapshot', () => {
    it('create_risk_snapshot — 基本作成', async () => {
      const result = await callTool({
        action: 'create_risk_snapshot',
        engagementId,
        score: 72.5,
        openCritical: 2,
        openHigh: 5,
        openMedium: 10,
        openLow: 3,
        openInfo: 1,
        openTotal: 21,
      });
      const snapshot = parseResponse<{
        id: string;
        engagementId: string;
        score: number;
        openCritical: number;
        openTotal: number;
      }>(result);
      expect(snapshot.id).toBeDefined();
      expect(snapshot.engagementId).toBe(engagementId);
      expect(snapshot.score).toBe(72.5);
      expect(snapshot.openCritical).toBe(2);
      expect(snapshot.openTotal).toBe(21);
    });

    it('get_risk_snapshot — 存在するID', async () => {
      const createResult = await callTool({
        action: 'create_risk_snapshot',
        engagementId,
        score: 50.0,
      });
      const { id } = parseResponse<{ id: string }>(createResult);

      const getResult = await callTool({ action: 'get_risk_snapshot', id });
      const snapshot = parseResponse<{ id: string; score: number }>(getResult);
      expect(snapshot.id).toBe(id);
      expect(snapshot.score).toBe(50.0);
    });

    it('get_risk_snapshot — 存在しないID', async () => {
      const result = await callTool({
        action: 'get_risk_snapshot',
        id: '00000000-0000-0000-0000-000000000000',
      });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('not found');
    });

    it('list_risk_snapshots — エンゲージメントフィルタ', async () => {
      await callTool({
        action: 'create_risk_snapshot',
        engagementId,
        score: 30.0,
      });
      await callTool({
        action: 'create_risk_snapshot',
        engagementId,
        score: 60.0,
      });

      const result = await callTool({
        action: 'list_risk_snapshots',
        engagementId,
      });
      const snapshots = parseResponse<Array<{ id: string }>>(result);
      expect(snapshots).toHaveLength(2);
    });

    it('latest_risk_snapshot — 最新取得', async () => {
      await callTool({
        action: 'create_risk_snapshot',
        engagementId,
        score: 30.0,
      });
      await callTool({
        action: 'create_risk_snapshot',
        engagementId,
        score: 85.0,
      });

      const result = await callTool({
        action: 'latest_risk_snapshot',
        engagementId,
      });
      const snapshot = parseResponse<{ score: number }>(result);
      expect(snapshot.score).toBe(85.0);
    });

    it('latest_risk_snapshot — スナップショットが存在しない場合', async () => {
      const result = await callTool({
        action: 'latest_risk_snapshot',
        engagementId,
      });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('No risk snapshot found');
    });
  });

  // =========================================================
  // バリデーションエラー
  // =========================================================

  describe('Validation', () => {
    it('missing required param — list_findings で engagementId 未指定', async () => {
      const result = await callTool({ action: 'list_findings' });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('engagementId parameter is required');
    });

    it('missing required param — upsert_finding で必須パラメータ不足', async () => {
      const r1 = await callTool({ action: 'upsert_finding' });
      expect(r1.isError).toBe(true);
      expect(getText(r1)).toContain('engagementId');

      const r2 = await callTool({ action: 'upsert_finding', engagementId });
      expect(r2.isError).toBe(true);
      expect(getText(r2)).toContain('canonicalKey');

      const r3 = await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'test:key',
      });
      expect(r3.isError).toBe(true);
      expect(getText(r3)).toContain('title');

      const r4 = await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'test:key',
        title: 'Test',
      });
      expect(r4.isError).toBe(true);
      expect(getText(r4)).toContain('severity');

      const r5 = await callTool({
        action: 'upsert_finding',
        engagementId,
        canonicalKey: 'test:key',
        title: 'Test',
        severity: 'high',
      });
      expect(r5.isError).toBe(true);
      expect(getText(r5)).toContain('confidence');
    });

    it('missing required param — get_finding で id 未指定', async () => {
      const result = await callTool({ action: 'get_finding' });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('id parameter is required');
    });

    it('missing required param — update_finding_state で id/state 未指定', async () => {
      const r1 = await callTool({ action: 'update_finding_state' });
      expect(r1.isError).toBe(true);
      expect(getText(r1)).toContain('id');

      const r2 = await callTool({
        action: 'update_finding_state',
        id: '00000000-0000-0000-0000-000000000000',
      });
      expect(r2.isError).toBe(true);
      expect(getText(r2)).toContain('state');
    });

    it('missing required param — list_finding_events で findingId 未指定', async () => {
      const result = await callTool({ action: 'list_finding_events' });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('findingId parameter is required');
    });

    it('missing required param — create_risk_snapshot で engagementId/score 未指定', async () => {
      const r1 = await callTool({ action: 'create_risk_snapshot' });
      expect(r1.isError).toBe(true);
      expect(getText(r1)).toContain('engagementId');

      const r2 = await callTool({
        action: 'create_risk_snapshot',
        engagementId,
      });
      expect(r2.isError).toBe(true);
      expect(getText(r2)).toContain('score');
    });

    it('missing required param — get_risk_snapshot で id 未指定', async () => {
      const result = await callTool({ action: 'get_risk_snapshot' });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('id parameter is required');
    });

    it('missing required param — list_risk_snapshots で engagementId 未指定', async () => {
      const result = await callTool({ action: 'list_risk_snapshots' });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('engagementId parameter is required');
    });

    it('missing required param — latest_risk_snapshot で engagementId 未指定', async () => {
      const result = await callTool({ action: 'latest_risk_snapshot' });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('engagementId parameter is required');
    });
  });

  // =========================================================
  // ツール登録確認
  // =========================================================

  it('findings ツールが登録されている', async () => {
    const result = await client.listTools();
    const toolNames = result.tools.map((t) => t.name);
    expect(toolNames).toContain('findings');
  });
});
