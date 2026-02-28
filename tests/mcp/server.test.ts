/**
 * sonobat — MCP Server 統合テスト
 *
 * InMemoryTransport でサーバーとクライアントをインメモリ接続し、
 * 全ツール・リソースの動作を検証する。
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrateDatabase } from '../../src/db/migrate.js';
import { createMcpServer } from '../../src/mcp/server.js';
import { HostRepository } from '../../src/db/repository/host-repository.js';
import { ArtifactRepository } from '../../src/db/repository/artifact-repository.js';
import { ServiceRepository } from '../../src/db/repository/service-repository.js';
import { VulnerabilityRepository } from '../../src/db/repository/vulnerability-repository.js';
import { CredentialRepository } from '../../src/db/repository/credential-repository.js';

function now(): string {
  return new Date().toISOString();
}

describe('MCP Server', () => {
  let db: InstanceType<typeof Database>;
  let client: Client;

  beforeEach(async () => {
    db = new Database(':memory:');
    migrateDatabase(db);

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

  it('17 ツールが登録されている', async () => {
    const result = await client.listTools();
    const toolNames = result.tools.map((t) => t.name).sort();

    expect(toolNames).toContain('list_hosts');
    expect(toolNames).toContain('get_host');
    expect(toolNames).toContain('list_services');
    expect(toolNames).toContain('list_endpoints');
    expect(toolNames).toContain('list_inputs');
    expect(toolNames).toContain('list_observations');
    expect(toolNames).toContain('list_credentials');
    expect(toolNames).toContain('list_vulnerabilities');
    expect(toolNames).toContain('ingest_file');
    expect(toolNames).toContain('propose');
    expect(toolNames).toContain('add_host');
    expect(toolNames).toContain('add_credential');
    expect(toolNames).toContain('add_vulnerability');
    expect(toolNames).toContain('link_cve');
    expect(toolNames).toContain('list_facts');
    expect(toolNames).toContain('run_datalog');
    expect(toolNames).toContain('query_attack_paths');
    expect(result.tools.length).toBe(17);
  });

  it('リソースが登録されている', async () => {
    const result = await client.listResources();
    const uris = result.resources.map((r) => r.uri).sort();

    expect(uris).toContain('sonobat://hosts');
    expect(uris).toContain('sonobat://summary');
  });

  // =========================================================
  // Query ツール
  // =========================================================

  it('list_hosts — 空の場合は空配列を返す', async () => {
    const result = await client.callTool({ name: 'list_hosts', arguments: {} });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const hosts = JSON.parse(text) as unknown[];
    expect(hosts).toHaveLength(0);
  });

  it('list_hosts — ホスト追加後は一覧に含まれる', async () => {
    const hostRepo = new HostRepository(db);
    hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

    const result = await client.callTool({ name: 'list_hosts', arguments: {} });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const hosts = JSON.parse(text) as Array<{ authority: string }>;
    expect(hosts).toHaveLength(1);
    expect(hosts[0].authority).toBe('10.0.0.1');
  });

  it('get_host — ホスト詳細を取得できる', async () => {
    const hostRepo = new HostRepository(db);
    const artifactRepo = new ArtifactRepository(db);
    const serviceRepo = new ServiceRepository(db);

    const host = hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });
    const artifact = artifactRepo.create({ tool: 'nmap', kind: 'tool_output', path: '/tmp/scan.xml', capturedAt: now() });
    serviceRepo.create({
      hostId: host.id, transport: 'tcp', port: 80, appProto: 'http',
      protoConfidence: 'high', state: 'open', evidenceArtifactId: artifact.id,
    });

    const result = await client.callTool({ name: 'get_host', arguments: { hostId: host.id } });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const detail = JSON.parse(text) as { authority: string; services: unknown[] };
    expect(detail.authority).toBe('10.0.0.1');
    expect(detail.services).toHaveLength(1);
  });

  it('get_host — 存在しないホストでエラーを返す', async () => {
    const result = await client.callTool({
      name: 'get_host',
      arguments: { hostId: '00000000-0000-0000-0000-000000000000' },
    });
    expect(result.isError).toBe(true);
  });

  it('list_services — サービス一覧を取得できる', async () => {
    const hostRepo = new HostRepository(db);
    const artifactRepo = new ArtifactRepository(db);
    const serviceRepo = new ServiceRepository(db);

    const host = hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });
    const artifact = artifactRepo.create({ tool: 'nmap', kind: 'tool_output', path: '/tmp/scan.xml', capturedAt: now() });
    serviceRepo.create({
      hostId: host.id, transport: 'tcp', port: 80, appProto: 'http',
      protoConfidence: 'high', state: 'open', evidenceArtifactId: artifact.id,
    });
    serviceRepo.create({
      hostId: host.id, transport: 'tcp', port: 443, appProto: 'https',
      protoConfidence: 'high', state: 'open', evidenceArtifactId: artifact.id,
    });

    const result = await client.callTool({ name: 'list_services', arguments: { hostId: host.id } });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const services = JSON.parse(text) as unknown[];
    expect(services).toHaveLength(2);
  });

  it('list_credentials — serviceId なしで全件取得', async () => {
    const hostRepo = new HostRepository(db);
    const artifactRepo = new ArtifactRepository(db);
    const serviceRepo = new ServiceRepository(db);
    const credentialRepo = new CredentialRepository(db);

    const host = hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });
    const artifact = artifactRepo.create({ tool: 'nmap', kind: 'tool_output', path: '/tmp/scan.xml', capturedAt: now() });
    const service = serviceRepo.create({
      hostId: host.id, transport: 'tcp', port: 80, appProto: 'http',
      protoConfidence: 'high', state: 'open', evidenceArtifactId: artifact.id,
    });
    credentialRepo.create({
      serviceId: service.id, username: 'admin', secret: 'pass',
      secretType: 'password', source: 'manual', confidence: 'high',
      evidenceArtifactId: artifact.id,
    });

    const result = await client.callTool({ name: 'list_credentials', arguments: {} });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const creds = JSON.parse(text) as unknown[];
    expect(creds).toHaveLength(1);
  });

  it('list_vulnerabilities — severity フィルタ', async () => {
    const hostRepo = new HostRepository(db);
    const artifactRepo = new ArtifactRepository(db);
    const serviceRepo = new ServiceRepository(db);
    const vulnRepo = new VulnerabilityRepository(db);

    const host = hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });
    const artifact = artifactRepo.create({ tool: 'nmap', kind: 'tool_output', path: '/tmp/scan.xml', capturedAt: now() });
    const service = serviceRepo.create({
      hostId: host.id, transport: 'tcp', port: 80, appProto: 'http',
      protoConfidence: 'high', state: 'open', evidenceArtifactId: artifact.id,
    });
    vulnRepo.create({
      serviceId: service.id, vulnType: 'sqli', title: 'SQL Injection',
      severity: 'critical', confidence: 'high', evidenceArtifactId: artifact.id,
    });
    vulnRepo.create({
      serviceId: service.id, vulnType: 'info_disclosure', title: 'Info Leak',
      severity: 'low', confidence: 'high', evidenceArtifactId: artifact.id,
    });

    const result = await client.callTool({
      name: 'list_vulnerabilities',
      arguments: { severity: 'critical' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const vulns = JSON.parse(text) as Array<{ severity: string }>;
    expect(vulns).toHaveLength(1);
    expect(vulns[0].severity).toBe('critical');
  });

  // =========================================================
  // Mutation ツール
  // =========================================================

  it('add_host — ホストを手動追加できる', async () => {
    const result = await client.callTool({
      name: 'add_host',
      arguments: { authority: '192.168.1.1', authorityKind: 'IP' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const host = JSON.parse(text) as { authority: string; id: string };
    expect(host.authority).toBe('192.168.1.1');
    expect(host.id).toBeDefined();
  });

  it('add_host — 既存ホストの場合は既存を返す', async () => {
    const hostRepo = new HostRepository(db);
    hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

    const result = await client.callTool({
      name: 'add_host',
      arguments: { authority: '10.0.0.1', authorityKind: 'IP' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toContain('already exists');
  });

  it('add_vulnerability — 脆弱性を手動追加できる', async () => {
    const hostRepo = new HostRepository(db);
    const artifactRepo = new ArtifactRepository(db);
    const serviceRepo = new ServiceRepository(db);

    const host = hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });
    const artifact = artifactRepo.create({ tool: 'nmap', kind: 'tool_output', path: '/tmp/scan.xml', capturedAt: now() });
    const service = serviceRepo.create({
      hostId: host.id, transport: 'tcp', port: 80, appProto: 'http',
      protoConfidence: 'high', state: 'open', evidenceArtifactId: artifact.id,
    });

    const result = await client.callTool({
      name: 'add_vulnerability',
      arguments: {
        serviceId: service.id,
        vulnType: 'xss',
        title: 'Reflected XSS',
        severity: 'high',
        confidence: 'medium',
      },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const vuln = JSON.parse(text) as { vulnType: string; title: string };
    expect(vuln.vulnType).toBe('xss');
    expect(vuln.title).toBe('Reflected XSS');
  });

  // =========================================================
  // Propose ツール
  // =========================================================

  it('propose — サービスがないホストで nmap_scan を提案', async () => {
    const hostRepo = new HostRepository(db);
    hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

    const result = await client.callTool({ name: 'propose', arguments: {} });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const actions = JSON.parse(text) as Array<{ kind: string }>;
    expect(actions.some((a) => a.kind === 'nmap_scan')).toBe(true);
  });

  it('propose — 全て揃っている場合はメッセージを返す', async () => {
    // DB にデータなし → ホストもない → 提案なし
    const result = await client.callTool({ name: 'propose', arguments: {} });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toContain('No actions proposed');
  });

  // =========================================================
  // リソース
  // =========================================================

  it('sonobat://hosts — ホスト一覧リソース', async () => {
    const hostRepo = new HostRepository(db);
    hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

    const result = await client.readResource({ uri: 'sonobat://hosts' });
    const text = (result.contents[0] as { text: string }).text;
    const hosts = JSON.parse(text) as Array<{ authority: string }>;
    expect(hosts).toHaveLength(1);
    expect(hosts[0].authority).toBe('10.0.0.1');
  });

  it('sonobat://summary — 統計リソース', async () => {
    const hostRepo = new HostRepository(db);
    hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });
    hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.2', resolvedIpsJson: '[]' });

    const result = await client.readResource({ uri: 'sonobat://summary' });
    const text = (result.contents[0] as { text: string }).text;
    const counts = JSON.parse(text) as Record<string, number>;
    expect(counts['hosts']).toBe(2);
    expect(counts['services']).toBe(0);
  });

  // =========================================================
  // Datalog ツール
  // =========================================================

  it('list_facts — データなしの場合はメッセージを返す', async () => {
    const result = await client.callTool({ name: 'list_facts', arguments: {} });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toBe('No facts found.');
  });

  it('list_facts — ホスト追加後はファクトを返す', async () => {
    const hostRepo = new HostRepository(db);
    hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

    const result = await client.callTool({ name: 'list_facts', arguments: { predicate: 'host' } });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toContain('host(');
    expect(text).toContain('"10.0.0.1"');
    expect(text).toContain('"IP"');
    expect(text).toMatch(/\.$/m);
  });

  it('list_facts — limit オプションで件数制限', async () => {
    const hostRepo = new HostRepository(db);
    hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });
    hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.2', resolvedIpsJson: '[]' });

    const result = await client.callTool({
      name: 'list_facts',
      arguments: { predicate: 'host', limit: 1 },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const lines = text.split('\n').filter((l: string) => l.trim().length > 0);
    expect(lines).toHaveLength(1);
  });

  it('run_datalog — 簡単なクエリを実行', async () => {
    const hostRepo = new HostRepository(db);
    const artifactRepo = new ArtifactRepository(db);
    const serviceRepo = new ServiceRepository(db);

    const host = hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });
    const artifact = artifactRepo.create({ tool: 'nmap', kind: 'tool_output', path: '/tmp/scan.xml', capturedAt: now() });
    serviceRepo.create({
      hostId: host.id, transport: 'tcp', port: 80, appProto: 'http',
      protoConfidence: 'high', state: 'open', evidenceArtifactId: artifact.id,
    });

    const program = [
      'reachable(Host, Port, AppProto) :- service(Host, _, _, Port, AppProto, "open").',
      '?- reachable(Host, Port, AppProto).',
    ].join('\n');

    const result = await client.callTool({
      name: 'run_datalog',
      arguments: { program },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toContain('Query: reachable(Host, Port, AppProto)');
    expect(text).toContain('Results (1 rows)');
    expect(text).toContain('80');
    expect(text).toContain('http');
    expect(text).toContain('Stats:');
  });

  it('run_datalog — 不正なプログラムでエラーを返す', async () => {
    const result = await client.callTool({
      name: 'run_datalog',
      arguments: { program: '??? invalid syntax' },
    });
    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toContain('Datalog error');
  });

  it('query_attack_paths — "list" で利用可能なパターンを返す', async () => {
    const result = await client.callTool({
      name: 'query_attack_paths',
      arguments: { pattern: 'list' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toContain('Available patterns:');
    expect(text).toContain('reachable_services');
    expect(text).toContain('critical_vulns');
    expect(text).toContain('[preset]');
  });

  it('query_attack_paths — プリセットパターンを実行', async () => {
    const hostRepo = new HostRepository(db);
    const artifactRepo = new ArtifactRepository(db);
    const serviceRepo = new ServiceRepository(db);

    const host = hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });
    const artifact = artifactRepo.create({ tool: 'nmap', kind: 'tool_output', path: '/tmp/scan.xml', capturedAt: now() });
    serviceRepo.create({
      hostId: host.id, transport: 'tcp', port: 443, appProto: 'https',
      protoConfidence: 'high', state: 'open', evidenceArtifactId: artifact.id,
    });

    const result = await client.callTool({
      name: 'query_attack_paths',
      arguments: { pattern: 'reachable_services' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toContain('Query: reachable(Host, Port, AppProto)');
    expect(text).toContain('443');
    expect(text).toContain('https');
  });

  it('query_attack_paths — 存在しないパターンで空結果を返す', async () => {
    const result = await client.callTool({
      name: 'query_attack_paths',
      arguments: { pattern: 'nonexistent_pattern' },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    expect(text).toContain('No query results.');
  });
});
