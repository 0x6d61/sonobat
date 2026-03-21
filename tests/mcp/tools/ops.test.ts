/**
 * sonobat — MCP Ops Tool テスト
 *
 * InMemoryTransport で MCP サーバーとクライアントをインメモリ接続し、
 * ops ツールの全 17 アクションを検証する。
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { registerOpsTools } from '../../../src/mcp/tools/ops.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

type TextContent = Array<{ type: string; text: string }>;

/** MCP ツール呼び出し結果からテキストをパースして返す */
function parseResult<T>(result: { content: unknown }): T {
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

describe('MCP Ops Tool', () => {
  let db: InstanceType<typeof Database>;
  let client: Client;

  beforeEach(async () => {
    db = new Database(':memory:');
    migrateDatabase(db);

    const server = new McpServer({ name: 'test', version: '0.0.0' });
    registerOpsTools(server, db);

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);

    client = new Client({ name: 'test-client', version: '0.0.0' });
    await client.connect(clientTransport);
  });

  afterEach(async () => {
    await client.close();
  });

  /** ops ツールを呼び出すヘルパー */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- MCP SDK callTool returns a complex union type
  async function callOps(args: Record<string, unknown>): Promise<any> {
    return await client.callTool({ name: 'ops', arguments: args });
  }

  // =========================================================
  // Engagement アクション
  // =========================================================

  describe('Engagement', () => {
    it('create_engagement → list_engagements → get_engagement — フルサイクル', async () => {
      // create
      const createResult = await callOps({
        action: 'create_engagement',
        name: 'Test Engagement',
        environment: 'prod',
      });
      const created = parseResult<{ id: string; name: string; environment: string }>(createResult);
      expect(created.name).toBe('Test Engagement');
      expect(created.environment).toBe('prod');
      expect(created.id).toBeDefined();

      // list
      const listResult = await callOps({ action: 'list_engagements' });
      const engagements = parseResult<Array<{ id: string }>>(listResult);
      expect(engagements).toHaveLength(1);
      expect(engagements[0].id).toBe(created.id);

      // get
      const getResult = await callOps({ action: 'get_engagement', id: created.id });
      const fetched = parseResult<{ id: string; name: string }>(getResult);
      expect(fetched.id).toBe(created.id);
      expect(fetched.name).toBe('Test Engagement');
    });

    it('create_engagement — デフォルト値が設定される', async () => {
      const result = await callOps({ action: 'create_engagement', name: 'Defaults Test' });
      const eng = parseResult<{
        environment: string;
        scopeJson: string;
        policyJson: string;
        status: string;
      }>(result);
      expect(eng.environment).toBe('stg');
      expect(eng.scopeJson).toBe('{}');
      expect(eng.policyJson).toBe('{}');
      expect(eng.status).toBe('active');
    });

    it('create_engagement — name 未指定でエラー', async () => {
      const result = await callOps({ action: 'create_engagement' });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('name parameter is required');
    });

    it('list_engagements — status フィルタ', async () => {
      await callOps({ action: 'create_engagement', name: 'Active', status: 'active' });
      await callOps({ action: 'create_engagement', name: 'Paused', status: 'paused' });

      const activeResult = await callOps({ action: 'list_engagements', status: 'active' });
      const active = parseResult<Array<{ name: string }>>(activeResult);
      expect(active).toHaveLength(1);
      expect(active[0].name).toBe('Active');
    });

    it('update_engagement — name と status を更新', async () => {
      const createResult = await callOps({
        action: 'create_engagement',
        name: 'Original',
      });
      const { id } = parseResult<{ id: string }>(createResult);

      const updateResult = await callOps({
        action: 'update_engagement',
        id,
        name: 'Updated',
        status: 'paused',
      });
      const updated = parseResult<{ name: string; status: string }>(updateResult);
      expect(updated.name).toBe('Updated');
      expect(updated.status).toBe('paused');
    });

    it('update_engagement — 存在しない ID でエラー', async () => {
      const result = await callOps({
        action: 'update_engagement',
        id: '00000000-0000-0000-0000-000000000000',
        name: 'test',
      });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('not found');
    });

    it('delete_engagement — 正常削除', async () => {
      const createResult = await callOps({
        action: 'create_engagement',
        name: 'ToDelete',
      });
      const { id } = parseResult<{ id: string }>(createResult);

      const deleteResult = await callOps({ action: 'delete_engagement', id });
      expect(getText(deleteResult)).toContain('deleted successfully');

      // 確認: 取得でエラー
      const getResult = await callOps({ action: 'get_engagement', id });
      expect(getResult.isError).toBe(true);
    });

    it('delete_engagement — 存在しない ID でエラー', async () => {
      const result = await callOps({
        action: 'delete_engagement',
        id: '00000000-0000-0000-0000-000000000000',
      });
      expect(result.isError).toBe(true);
    });

    it('get_engagement — id 未指定でエラー', async () => {
      const result = await callOps({ action: 'get_engagement' });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('id parameter is required');
    });
  });

  // =========================================================
  // Run アクション
  // =========================================================

  describe('Run', () => {
    let engagementId: string;

    beforeEach(async () => {
      const result = await callOps({ action: 'create_engagement', name: 'Run Test' });
      engagementId = parseResult<{ id: string }>(result).id;
    });

    it('create_run → list_runs → get_run — フルサイクル', async () => {
      // create
      const createResult = await callOps({
        action: 'create_run',
        engagementId,
        triggerKind: 'manual',
        status: 'running',
      });
      const run = parseResult<{ id: string; engagementId: string; status: string }>(createResult);
      expect(run.engagementId).toBe(engagementId);
      expect(run.status).toBe('running');

      // list
      const listResult = await callOps({ action: 'list_runs', engagementId });
      const runs = parseResult<Array<{ id: string }>>(listResult);
      expect(runs).toHaveLength(1);
      expect(runs[0].id).toBe(run.id);

      // get
      const getResult = await callOps({ action: 'get_run', id: run.id });
      const fetched = parseResult<{ id: string; triggerKind: string }>(getResult);
      expect(fetched.id).toBe(run.id);
      expect(fetched.triggerKind).toBe('manual');
    });

    it('create_run — 必須パラメータ不足でエラー', async () => {
      const r1 = await callOps({ action: 'create_run' });
      expect(r1.isError).toBe(true);
      expect(getText(r1)).toContain('engagementId');

      const r2 = await callOps({ action: 'create_run', engagementId });
      expect(r2.isError).toBe(true);
      expect(getText(r2)).toContain('triggerKind');

      const r3 = await callOps({
        action: 'create_run',
        engagementId,
        triggerKind: 'manual',
      });
      expect(r3.isError).toBe(true);
      expect(getText(r3)).toContain('status');
    });

    it('update_run_status — succeeded にすると finishedAt が設定される', async () => {
      const createResult = await callOps({
        action: 'create_run',
        engagementId,
        triggerKind: 'manual',
        status: 'running',
      });
      const { id } = parseResult<{ id: string }>(createResult);

      const updateResult = await callOps({
        action: 'update_run_status',
        id,
        status: 'succeeded',
        summaryJson: '{"findings":0}',
      });
      const updated = parseResult<{
        status: string;
        finishedAt: string;
        summaryJson: string;
      }>(updateResult);
      expect(updated.status).toBe('succeeded');
      expect(updated.finishedAt).toBeDefined();
      expect(updated.summaryJson).toBe('{"findings":0}');
    });

    it('update_run_status — 必須パラメータ不足でエラー', async () => {
      const r1 = await callOps({ action: 'update_run_status' });
      expect(r1.isError).toBe(true);
      expect(getText(r1)).toContain('id');

      const r2 = await callOps({
        action: 'update_run_status',
        id: '00000000-0000-0000-0000-000000000000',
      });
      expect(r2.isError).toBe(true);
      expect(getText(r2)).toContain('status');
    });

    it('get_run — 存在しない ID でエラー', async () => {
      const result = await callOps({
        action: 'get_run',
        id: '00000000-0000-0000-0000-000000000000',
      });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('not found');
    });

    it('list_runs — limit パラメータが機能する', async () => {
      await callOps({
        action: 'create_run',
        engagementId,
        triggerKind: 'manual',
        status: 'running',
      });
      await callOps({
        action: 'create_run',
        engagementId,
        triggerKind: 'schedule',
        status: 'pending',
      });

      const result = await callOps({ action: 'list_runs', engagementId, limit: 1 });
      const runs = parseResult<Array<{ id: string }>>(result);
      expect(runs).toHaveLength(1);
    });
  });

  // =========================================================
  // ActionQueue アクション
  // =========================================================

  describe('ActionQueue', () => {
    let engagementId: string;

    beforeEach(async () => {
      const result = await callOps({ action: 'create_engagement', name: 'Queue Test' });
      engagementId = parseResult<{ id: string }>(result).id;
    });

    it('enqueue_action → poll_action → complete_action — フルライフサイクル', async () => {
      // enqueue
      const enqueueResult = await callOps({
        action: 'enqueue_action',
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:10.0.0.1',
      });
      const item = parseResult<{ id: string; state: string; kind: string }>(enqueueResult);
      expect(item.state).toBe('queued');
      expect(item.kind).toBe('nmap_scan');

      // poll
      const pollResult = await callOps({
        action: 'poll_action',
        leaseOwner: 'worker-1',
      });
      const polled = parseResult<{ id: string; state: string; leaseOwner: string }>(pollResult);
      expect(polled.id).toBe(item.id);
      expect(polled.state).toBe('running');
      expect(polled.leaseOwner).toBe('worker-1');

      // complete
      const completeResult = await callOps({
        action: 'complete_action',
        id: item.id,
      });
      expect(getText(completeResult)).toContain('completed successfully');
    });

    it('enqueue_action — 必須パラメータ不足でエラー', async () => {
      const r1 = await callOps({ action: 'enqueue_action' });
      expect(r1.isError).toBe(true);
      expect(getText(r1)).toContain('engagementId');

      const r2 = await callOps({ action: 'enqueue_action', engagementId });
      expect(r2.isError).toBe(true);
      expect(getText(r2)).toContain('kind');

      const r3 = await callOps({
        action: 'enqueue_action',
        engagementId,
        kind: 'nmap_scan',
      });
      expect(r3.isError).toBe(true);
      expect(getText(r3)).toContain('dedupeKey');
    });

    it('poll_action — キューが空の場合のメッセージ', async () => {
      const result = await callOps({
        action: 'poll_action',
        leaseOwner: 'worker-1',
      });
      expect(getText(result)).toContain('No action available');
    });

    it('poll_action — leaseOwner 未指定でエラー', async () => {
      const result = await callOps({ action: 'poll_action' });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('leaseOwner');
    });

    it('fail_action — リトライ可能な場合は queued に戻る', async () => {
      const enqueueResult = await callOps({
        action: 'enqueue_action',
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:fail-test',
        maxAttempts: 3,
      });
      const { id } = parseResult<{ id: string }>(enqueueResult);

      // poll
      await callOps({ action: 'poll_action', leaseOwner: 'worker-1' });

      // fail
      const failResult = await callOps({
        action: 'fail_action',
        id,
        errorMessage: 'connection timeout',
      });
      const afterFail = parseResult<{ state: string; lastError: string }>(failResult);
      expect(afterFail.state).toBe('queued');
      expect(afterFail.lastError).toBe('connection timeout');
    });

    it('fail_action — dead letter (maxAttempts=1)', async () => {
      const enqueueResult = await callOps({
        action: 'enqueue_action',
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:dead-letter',
        maxAttempts: 1,
      });
      const { id } = parseResult<{ id: string }>(enqueueResult);

      // poll (attempt_count → 1)
      await callOps({ action: 'poll_action', leaseOwner: 'worker-1' });

      // fail (attempt_count=1 >= maxAttempts=1 → dead letter)
      const failResult = await callOps({
        action: 'fail_action',
        id,
        errorMessage: 'permanent failure',
      });
      const afterFail = parseResult<{ state: string }>(failResult);
      expect(afterFail.state).toBe('failed');
    });

    it('fail_action — 必須パラメータ不足でエラー', async () => {
      const r1 = await callOps({ action: 'fail_action' });
      expect(r1.isError).toBe(true);
      expect(getText(r1)).toContain('id');

      const r2 = await callOps({
        action: 'fail_action',
        id: '00000000-0000-0000-0000-000000000000',
      });
      expect(r2.isError).toBe(true);
      expect(getText(r2)).toContain('errorMessage');
    });

    it('cancel_action — 正常キャンセル', async () => {
      const enqueueResult = await callOps({
        action: 'enqueue_action',
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:cancel-test',
      });
      const { id } = parseResult<{ id: string }>(enqueueResult);

      const cancelResult = await callOps({ action: 'cancel_action', id });
      expect(getText(cancelResult)).toContain('cancelled successfully');
    });

    it('cancel_action — 存在しない ID でエラー', async () => {
      const result = await callOps({
        action: 'cancel_action',
        id: '00000000-0000-0000-0000-000000000000',
      });
      expect(result.isError).toBe(true);
    });

    it('list_actions — state フィルタ', async () => {
      await callOps({
        action: 'enqueue_action',
        engagementId,
        kind: 'nmap_scan',
        dedupeKey: 'nmap:list-a',
      });
      await callOps({
        action: 'enqueue_action',
        engagementId,
        kind: 'nuclei_scan',
        dedupeKey: 'nuclei:list-b',
      });

      // 1つ目を poll して running にする
      await callOps({ action: 'poll_action', leaseOwner: 'worker-1' });

      const queuedResult = await callOps({
        action: 'list_actions',
        engagementId,
        state: 'queued',
      });
      const queued = parseResult<Array<{ kind: string }>>(queuedResult);
      expect(queued).toHaveLength(1);
      expect(queued[0].kind).toBe('nuclei_scan');

      const runningResult = await callOps({
        action: 'list_actions',
        engagementId,
        state: 'running',
      });
      const running = parseResult<Array<{ kind: string }>>(runningResult);
      expect(running).toHaveLength(1);
      expect(running[0].kind).toBe('nmap_scan');
    });

    it('list_actions — engagementId 未指定でエラー', async () => {
      const result = await callOps({ action: 'list_actions' });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('engagementId');
    });
  });

  // =========================================================
  // ActionExecution アクション
  // =========================================================

  describe('ActionExecution', () => {
    let engagementId: string;
    let actionId: string;
    let runId: string;

    beforeEach(async () => {
      // engagement を作成
      const engResult = await callOps({
        action: 'create_engagement',
        name: 'Exec Test',
      });
      engagementId = parseResult<{ id: string }>(engResult).id;

      // run を作成
      const runResult = await callOps({
        action: 'create_run',
        engagementId,
        triggerKind: 'manual',
        status: 'running',
      });
      runId = parseResult<{ id: string }>(runResult).id;

      // action を直接 DB に挿入（ops ツール経由で enqueue してもよいが、
      // execution テストのために action_id が必要なので直接挿入）
      const crypto = await import('node:crypto');
      actionId = crypto.randomUUID();
      const now = new Date().toISOString();
      db.prepare(
        `INSERT INTO action_queue (id, engagement_id, run_id, kind, priority, dedupe_key, params_json, state, attempt_count, max_attempts, available_at, created_at, updated_at)
         VALUES (?, ?, ?, 'nmap_scan', 100, ?, '{}', 'running', 1, 3, ?, ?, ?)`,
      ).run(actionId, engagementId, runId, `dedupe-${actionId}`, now, now, now);

      // execution を直接 DB に挿入
      const execId = crypto.randomUUID();
      db.prepare(
        `INSERT INTO action_executions (id, action_id, run_id, executor, input_json, output_json, started_at)
         VALUES (?, ?, ?, 'nmap-executor', '{}', '{}', ?)`,
      ).run(execId, actionId, runId, now);
    });

    it('get_execution — 存在する execution を取得できる', async () => {
      // まず list_executions で ID を取得
      const listResult = await callOps({
        action: 'list_executions',
        actionId,
      });
      const executions = parseResult<Array<{ id: string; executor: string }>>(listResult);
      expect(executions).toHaveLength(1);

      // get_execution
      const getResult = await callOps({
        action: 'get_execution',
        id: executions[0].id,
      });
      const exec = parseResult<{ id: string; executor: string; actionId: string }>(getResult);
      expect(exec.id).toBe(executions[0].id);
      expect(exec.executor).toBe('nmap-executor');
      expect(exec.actionId).toBe(actionId);
    });

    it('get_execution — 存在しない ID でエラー', async () => {
      const result = await callOps({
        action: 'get_execution',
        id: '00000000-0000-0000-0000-000000000000',
      });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('not found');
    });

    it('get_execution — id 未指定でエラー', async () => {
      const result = await callOps({ action: 'get_execution' });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('id parameter is required');
    });

    it('list_executions — actionId でフィルタ', async () => {
      const result = await callOps({
        action: 'list_executions',
        actionId,
      });
      const executions = parseResult<Array<{ actionId: string }>>(result);
      expect(executions).toHaveLength(1);
      expect(executions[0].actionId).toBe(actionId);
    });

    it('list_executions — runId でフィルタ', async () => {
      const result = await callOps({
        action: 'list_executions',
        runId,
      });
      const executions = parseResult<Array<{ runId: string }>>(result);
      expect(executions).toHaveLength(1);
      expect(executions[0].runId).toBe(runId);
    });

    it('list_executions — actionId も runId も未指定でエラー', async () => {
      const result = await callOps({ action: 'list_executions' });
      expect(result.isError).toBe(true);
      expect(getText(result)).toContain('actionId or runId parameter is required');
    });
  });

  // =========================================================
  // ツール登録確認
  // =========================================================

  it('ops ツールが登録されている', async () => {
    const result = await client.listTools();
    const toolNames = result.tools.map((t) => t.name);
    expect(toolNames).toContain('ops');
  });
});
