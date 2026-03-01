/**
 * sonobat — MCP Server 統合テスト (v4 graph-native)
 *
 * InMemoryTransport でサーバーとクライアントをインメモリ接続し、
 * 全 6 ツール・リソースの動作を検証する。
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrateDatabase } from '../../src/db/migrate.js';
import { createMcpServer } from '../../src/mcp/server.js';
import { NodeRepository } from '../../src/db/repository/node-repository.js';
import { EdgeRepository } from '../../src/db/repository/edge-repository.js';
import { TechniqueDocRepository } from '../../src/db/repository/technique-doc-repository.js';

describe('MCP Server', () => {
  let db: InstanceType<typeof Database>;
  let client: Client;
  let nodeRepo: NodeRepository;
  let edgeRepo: EdgeRepository;

  beforeEach(async () => {
    db = new Database(':memory:');
    migrateDatabase(db);

    nodeRepo = new NodeRepository(db);
    edgeRepo = new EdgeRepository(db);

    const server = createMcpServer(db);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    await server.connect(serverTransport);
    client = new Client({ name: 'test-client', version: '1.0.0' });
    await client.connect(clientTransport);
  });

  afterEach(async () => {
    await client.close();
  });

  // =========================================================
  // ツール登録確認
  // =========================================================

  it('6 ツールが登録されている', async () => {
    const result = await client.listTools();
    const toolNames = result.tools.map((t) => t.name).sort();

    expect(toolNames).toContain('query');
    expect(toolNames).toContain('mutate');
    expect(toolNames).toContain('ingest_file');
    expect(toolNames).toContain('propose');
    expect(toolNames).toContain('search_kb');
    expect(toolNames).toContain('index_kb');
    expect(result.tools.length).toBe(6);
  });

  it('リソースが登録されている', async () => {
    const result = await client.listResources();
    const uris = result.resources.map((r) => r.uri).sort();

    expect(uris).toContain('sonobat://nodes');
    expect(uris).toContain('sonobat://summary');
    expect(uris).toContain('sonobat://techniques/categories');
  });

  // =========================================================
  // Query ツール — list_nodes
  // =========================================================

  it('query list_nodes — 空の場合は空配列を返す', async () => {
    const result = await client.callTool({
      name: 'query',
      arguments: { action: 'list_nodes', kind: 'host' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const nodes = JSON.parse(text) as unknown[];
    expect(nodes).toHaveLength(0);
  });

  it('query list_nodes — ノード追加後は一覧に含まれる', async () => {
    nodeRepo.create('host', { authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

    const result = await client.callTool({
      name: 'query',
      arguments: { action: 'list_nodes', kind: 'host' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const nodes = JSON.parse(text) as Array<{ props: { authority: string } }>;
    expect(nodes).toHaveLength(1);
    expect(nodes[0].props.authority).toBe('10.0.0.1');
  });

  it('query list_nodes — kind 未指定でエラーを返す', async () => {
    const result = await client.callTool({
      name: 'query',
      arguments: { action: 'list_nodes' },
    });
    expect(result.isError).toBe(true);
  });

  it('query list_nodes — 無効な kind でエラーを返す', async () => {
    const result = await client.callTool({
      name: 'query',
      arguments: { action: 'list_nodes', kind: 'invalid_kind' },
    });
    expect(result.isError).toBe(true);
  });

  // =========================================================
  // Query ツール — get_node
  // =========================================================

  it('query get_node — ノード詳細を取得できる', async () => {
    const host = nodeRepo.create('host', {
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const svc = nodeRepo.create(
      'service',
      {
        transport: 'tcp',
        port: 80,
        appProto: 'http',
        protoConfidence: 'high',
        state: 'open',
      },
      undefined,
      host.id,
    );
    edgeRepo.create('HOST_SERVICE', host.id, svc.id);

    const result = await client.callTool({
      name: 'query',
      arguments: { action: 'get_node', id: host.id },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const detail = JSON.parse(text) as {
      props: { authority: string };
      outEdges: unknown[];
      adjacentNodes: unknown[];
    };
    expect(detail.props.authority).toBe('10.0.0.1');
    expect(detail.outEdges).toHaveLength(1);
    expect(detail.adjacentNodes).toHaveLength(1);
  });

  it('query get_node — 存在しないノードでエラーを返す', async () => {
    const result = await client.callTool({
      name: 'query',
      arguments: { action: 'get_node', id: '00000000-0000-0000-0000-000000000000' },
    });
    expect(result.isError).toBe(true);
  });

  // =========================================================
  // Query ツール — traverse
  // =========================================================

  it('query traverse — グラフ走査ができる', async () => {
    const host = nodeRepo.create('host', {
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const svc = nodeRepo.create(
      'service',
      {
        transport: 'tcp',
        port: 80,
        appProto: 'http',
        protoConfidence: 'high',
        state: 'open',
      },
      undefined,
      host.id,
    );
    edgeRepo.create('HOST_SERVICE', host.id, svc.id);

    const result = await client.callTool({
      name: 'query',
      arguments: { action: 'traverse', startId: host.id, depth: 2 },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const nodes = JSON.parse(text) as unknown[];
    expect(nodes.length).toBeGreaterThanOrEqual(1);
  });

  it('query traverse — startId 未指定でエラーを返す', async () => {
    const result = await client.callTool({
      name: 'query',
      arguments: { action: 'traverse' },
    });
    expect(result.isError).toBe(true);
  });

  // =========================================================
  // Query ツール — summary
  // =========================================================

  it('query summary — 統計情報を返す', async () => {
    nodeRepo.create('host', { authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });
    nodeRepo.create('host', { authorityKind: 'IP', authority: '10.0.0.2', resolvedIpsJson: '[]' });

    const result = await client.callTool({
      name: 'query',
      arguments: { action: 'summary' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const summary = JSON.parse(text) as { nodes: Record<string, number> };
    expect(summary.nodes.host).toBe(2);
    expect(summary.nodes.service).toBe(0);
  });

  // =========================================================
  // Query ツール — attack_paths
  // =========================================================

  it('query attack_paths — プリセットパターンを実行', async () => {
    const host = nodeRepo.create('host', {
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const svc = nodeRepo.create(
      'service',
      {
        transport: 'tcp',
        port: 443,
        appProto: 'https',
        protoConfidence: 'high',
        state: 'open',
      },
      undefined,
      host.id,
    );
    edgeRepo.create('HOST_SERVICE', host.id, svc.id);

    const result = await client.callTool({
      name: 'query',
      arguments: { action: 'attack_paths', pattern: 'vuln_by_host' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const parsed = JSON.parse(text) as unknown[];
    expect(Array.isArray(parsed)).toBe(true);
  });

  it('query attack_paths — pattern 未指定でエラーを返す', async () => {
    const result = await client.callTool({
      name: 'query',
      arguments: { action: 'attack_paths' },
    });
    expect(result.isError).toBe(true);
  });

  // =========================================================
  // Mutate ツール — add_node
  // =========================================================

  it('mutate add_node — ホストノードを手動追加できる', async () => {
    const result = await client.callTool({
      name: 'mutate',
      arguments: {
        action: 'add_node',
        kind: 'host',
        propsJson: JSON.stringify({
          authorityKind: 'IP',
          authority: '192.168.1.1',
          resolvedIpsJson: '[]',
        }),
      },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const node = JSON.parse(text) as { props: { authority: string }; created: boolean };
    expect(node.props.authority).toBe('192.168.1.1');
    expect(node.created).toBe(true);
  });

  it('mutate add_node — 既存 natural_key で upsert（created=false）', async () => {
    nodeRepo.create('host', { authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

    const result = await client.callTool({
      name: 'mutate',
      arguments: {
        action: 'add_node',
        kind: 'host',
        propsJson: JSON.stringify({
          authorityKind: 'IP',
          authority: '10.0.0.1',
          resolvedIpsJson: '[]',
        }),
      },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const node = JSON.parse(text) as { created: boolean };
    expect(node.created).toBe(false);
  });

  it('mutate add_node — 無効な kind でエラーを返す', async () => {
    const result = await client.callTool({
      name: 'mutate',
      arguments: { action: 'add_node', kind: 'unknown_kind', propsJson: '{}' },
    });
    expect(result.isError).toBe(true);
  });

  it('mutate add_node — 無効な props でエラーを返す', async () => {
    const result = await client.callTool({
      name: 'mutate',
      arguments: {
        action: 'add_node',
        kind: 'host',
        propsJson: JSON.stringify({ invalid: 'field' }),
      },
    });
    expect(result.isError).toBe(true);
  });

  // =========================================================
  // Mutate ツール — add_edge
  // =========================================================

  it('mutate add_edge — エッジを追加できる', async () => {
    const host = nodeRepo.create('host', {
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const svc = nodeRepo.create(
      'service',
      {
        transport: 'tcp',
        port: 80,
        appProto: 'http',
        protoConfidence: 'high',
        state: 'open',
      },
      undefined,
      host.id,
    );

    const result = await client.callTool({
      name: 'mutate',
      arguments: {
        action: 'add_edge',
        edgeKind: 'HOST_SERVICE',
        sourceId: host.id,
        targetId: svc.id,
      },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const edge = JSON.parse(text) as { kind: string; created: boolean };
    expect(edge.kind).toBe('HOST_SERVICE');
    expect(edge.created).toBe(true);
  });

  it('mutate add_edge — 無効な edgeKind でエラーを返す', async () => {
    const result = await client.callTool({
      name: 'mutate',
      arguments: {
        action: 'add_edge',
        edgeKind: 'INVALID_KIND',
        sourceId: 'a',
        targetId: 'b',
      },
    });
    expect(result.isError).toBe(true);
  });

  // =========================================================
  // Mutate ツール — update_node
  // =========================================================

  it('mutate update_node — ノード props を更新できる', async () => {
    const host = nodeRepo.create('host', {
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });

    const result = await client.callTool({
      name: 'mutate',
      arguments: {
        action: 'update_node',
        id: host.id,
        propsJson: JSON.stringify({
          authorityKind: 'IP',
          authority: '10.0.0.1',
          resolvedIpsJson: '["10.0.0.1"]',
        }),
      },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const updated = JSON.parse(text) as { props: { resolvedIpsJson: string } };
    expect(updated.props.resolvedIpsJson).toBe('["10.0.0.1"]');
  });

  it('mutate update_node — 存在しないノードでエラーを返す', async () => {
    const result = await client.callTool({
      name: 'mutate',
      arguments: {
        action: 'update_node',
        id: '00000000-0000-0000-0000-000000000000',
        propsJson: JSON.stringify({ authority: 'test' }),
      },
    });
    expect(result.isError).toBe(true);
  });

  // =========================================================
  // Mutate ツール — delete_node
  // =========================================================

  it('mutate delete_node — ノードを削除できる', async () => {
    const host = nodeRepo.create('host', {
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });

    const result = await client.callTool({
      name: 'mutate',
      arguments: { action: 'delete_node', id: host.id },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toContain('deleted successfully');

    // 確認: ノードが存在しないこと
    expect(nodeRepo.findById(host.id)).toBeUndefined();
  });

  it('mutate delete_node — 存在しないノードでエラーを返す', async () => {
    const result = await client.callTool({
      name: 'mutate',
      arguments: { action: 'delete_node', id: '00000000-0000-0000-0000-000000000000' },
    });
    expect(result.isError).toBe(true);
  });

  // =========================================================
  // Propose ツール
  // =========================================================

  it('propose — サービスがないホストで nmap_scan を提案', async () => {
    nodeRepo.create('host', { authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

    const result = await client.callTool({ name: 'propose', arguments: {} });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const actions = JSON.parse(text) as Array<{ kind: string }>;
    expect(actions.some((a) => a.kind === 'nmap_scan')).toBe(true);
  });

  it('propose — 全て揃っている場合はメッセージを返す', async () => {
    const result = await client.callTool({ name: 'propose', arguments: {} });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toContain('No actions proposed');
  });

  // =========================================================
  // Knowledge Base ツール
  // =========================================================

  it('search_kb — インデックスが空の場合はメッセージを返す', async () => {
    const result = await client.callTool({
      name: 'search_kb',
      arguments: { query: 'docker breakout' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toContain('No results found');
  });

  it('search_kb — インデックス後に検索結果を返す', async () => {
    const techDocRepo = new TechniqueDocRepository(db);
    techDocRepo.index([
      {
        source: 'hacktricks',
        filePath: 'linux-hardening/docker-breakout.md',
        title: 'Docker Breakout',
        category: 'linux-hardening',
        content: 'Docker container escape techniques using nsenter.',
        chunkIndex: 0,
      },
    ]);

    const result = await client.callTool({
      name: 'search_kb',
      arguments: { query: 'docker escape' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const parsed = JSON.parse(text) as Array<{ title: string }>;
    expect(parsed.length).toBeGreaterThanOrEqual(1);
    expect(parsed[0].title).toBe('Docker Breakout');
  });

  it('search_kb — category フィルタが機能する', async () => {
    const techDocRepo = new TechniqueDocRepository(db);
    techDocRepo.index([
      {
        source: 'hacktricks',
        filePath: 'linux-hardening/priv-esc.md',
        title: 'Linux Priv Esc',
        category: 'linux-hardening',
        content: 'Privilege escalation on Linux systems.',
        chunkIndex: 0,
      },
      {
        source: 'hacktricks',
        filePath: 'windows-hardening/priv-esc.md',
        title: 'Windows Priv Esc',
        category: 'windows-hardening',
        content: 'Privilege escalation on Windows systems.',
        chunkIndex: 0,
      },
    ]);

    const result = await client.callTool({
      name: 'search_kb',
      arguments: { query: 'privilege escalation', category: 'windows-hardening' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const parsed = JSON.parse(text) as Array<{ category: string }>;
    expect(parsed).toHaveLength(1);
    expect(parsed[0].category).toBe('windows-hardening');
  });

  // =========================================================
  // リソース
  // =========================================================

  it('sonobat://nodes — ノード一覧リソース', async () => {
    nodeRepo.create('host', { authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

    const result = await client.readResource({ uri: 'sonobat://nodes' });
    const text = (result.contents[0] as { text: string }).text;
    const nodes = JSON.parse(text) as Array<{ kind: string }>;
    expect(nodes).toHaveLength(1);
    expect(nodes[0].kind).toBe('host');
  });

  it('sonobat://summary — 統計リソース', async () => {
    nodeRepo.create('host', { authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });
    nodeRepo.create('host', { authorityKind: 'IP', authority: '10.0.0.2', resolvedIpsJson: '[]' });

    const result = await client.readResource({ uri: 'sonobat://summary' });
    const text = (result.contents[0] as { text: string }).text;
    const counts = JSON.parse(text) as { nodes: Record<string, number> };
    expect(counts.nodes.host).toBe(2);
    expect(counts.nodes.service).toBe(0);
  });

  it('sonobat://techniques/categories — カテゴリ一覧リソース', async () => {
    const techDocRepo = new TechniqueDocRepository(db);
    techDocRepo.index([
      {
        source: 'hacktricks',
        filePath: 'web/sqli.md',
        title: 'SQLi',
        category: 'web',
        content: 'SQL injection.',
        chunkIndex: 0,
      },
      {
        source: 'hacktricks',
        filePath: 'linux/priv-esc.md',
        title: 'Priv Esc',
        category: 'linux',
        content: 'Privilege escalation.',
        chunkIndex: 0,
      },
    ]);

    const result = await client.readResource({ uri: 'sonobat://techniques/categories' });
    const text = (result.contents[0] as { text: string }).text;
    const categories = JSON.parse(text) as string[];
    expect(categories).toContain('web');
    expect(categories).toContain('linux');
  });
});
