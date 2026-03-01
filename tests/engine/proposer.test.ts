import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../src/db/migrate.js';
import { propose } from '../../src/engine/proposer.js';
import { NodeRepository } from '../../src/db/repository/node-repository.js';
import { EdgeRepository } from '../../src/db/repository/edge-repository.js';
import crypto from 'node:crypto';

// =========================================================
// Helper functions
// =========================================================

function createTestDb(): InstanceType<typeof Database> {
  const db = new Database(':memory:');
  migrateDatabase(db);
  return db;
}

function insertArtifact(db: InstanceType<typeof Database>): string {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(
    'INSERT INTO artifacts (id, tool, kind, path, captured_at) VALUES (?, ?, ?, ?, ?)',
  ).run(id, 'nmap', 'tool_output', '/tmp/scan.xml', now);
  return id;
}

function createHostNode(nodeRepo: NodeRepository, authority: string): string {
  const node = nodeRepo.create('host', {
    authorityKind: 'IP',
    authority,
    resolvedIpsJson: '[]',
  });
  return node.id;
}

function createServiceNode(
  nodeRepo: NodeRepository,
  edgeRepo: EdgeRepository,
  hostId: string,
  port: number,
  appProto: string,
  artifactId: string,
): string {
  const node = nodeRepo.create(
    'service',
    {
      transport: 'tcp',
      port,
      appProto,
      protoConfidence: 'high',
      state: 'open',
    },
    artifactId,
    hostId,
  );
  edgeRepo.create('HOST_SERVICE', hostId, node.id, artifactId);
  return node.id;
}

function createEndpointNode(
  nodeRepo: NodeRepository,
  edgeRepo: EdgeRepository,
  serviceId: string,
  method: string,
  path: string,
  artifactId: string,
  baseUri: string,
): string {
  const node = nodeRepo.create(
    'endpoint',
    {
      baseUri,
      method,
      path,
    },
    artifactId,
    serviceId,
  );
  edgeRepo.create('SERVICE_ENDPOINT', serviceId, node.id, artifactId);
  return node.id;
}

function createInputNode(
  nodeRepo: NodeRepository,
  edgeRepo: EdgeRepository,
  serviceId: string,
  endpointId: string,
  location: string,
  name: string,
  artifactId: string,
): string {
  const node = nodeRepo.create(
    'input',
    {
      location,
      name,
    },
    undefined,
    serviceId,
  );
  edgeRepo.create('ENDPOINT_INPUT', endpointId, node.id, artifactId);
  return node.id;
}

function createObservationNode(
  nodeRepo: NodeRepository,
  edgeRepo: EdgeRepository,
  inputId: string,
  rawValue: string,
  artifactId: string,
): string {
  const node = nodeRepo.create(
    'observation',
    {
      rawValue,
      normValue: rawValue,
      source: 'ffuf_url',
      confidence: 'high',
      observedAt: new Date().toISOString(),
    },
    artifactId,
  );
  edgeRepo.create('INPUT_OBSERVATION', inputId, node.id, artifactId);
  return node.id;
}

function createVhostNode(
  nodeRepo: NodeRepository,
  edgeRepo: EdgeRepository,
  hostId: string,
  hostname: string,
  artifactId: string,
): string {
  const node = nodeRepo.create(
    'vhost',
    {
      hostname,
      source: 'cert',
    },
    artifactId,
    hostId,
  );
  edgeRepo.create('HOST_VHOST', hostId, node.id, artifactId);
  return node.id;
}

function createVulnerabilityNode(
  nodeRepo: NodeRepository,
  edgeRepo: EdgeRepository,
  serviceId: string,
  vulnType: string,
  title: string,
  artifactId: string,
  status: string = 'unverified',
): string {
  const node = nodeRepo.create(
    'vulnerability',
    {
      vulnType,
      title,
      severity: 'critical',
      confidence: 'high',
      status,
    },
    artifactId,
  );
  edgeRepo.create('SERVICE_VULNERABILITY', serviceId, node.id, artifactId);
  return node.id;
}

// =========================================================
// Tests
// =========================================================

describe('Proposer (graph-native)', () => {
  let db: InstanceType<typeof Database>;
  let nodeRepo: NodeRepository;
  let edgeRepo: EdgeRepository;

  beforeEach(() => {
    db = createTestDb();
    nodeRepo = new NodeRepository(db);
    edgeRepo = new EdgeRepository(db);
  });

  it('propose — ホストにサービスがない場合 nmap_scan を提案', () => {
    createHostNode(nodeRepo, '10.0.0.1');

    const actions = propose(db);

    expect(actions.length).toBeGreaterThanOrEqual(1);
    expect(actions.some((a) => a.kind === 'nmap_scan')).toBe(true);
    const nmapAction = actions.find((a) => a.kind === 'nmap_scan');
    expect(nmapAction?.command).toContain('10.0.0.1');
  });

  it('propose — HTTP サービスにエンドポイントがない場合 ffuf_discovery を提案', () => {
    const hostId = createHostNode(nodeRepo, '10.0.0.1');
    const artifactId = insertArtifact(db);
    createServiceNode(nodeRepo, edgeRepo, hostId, 80, 'http', artifactId);

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'ffuf_discovery')).toBe(true);
  });

  it('propose — エンドポイントに input がない場合 parameter_discovery を提案', () => {
    const hostId = createHostNode(nodeRepo, '10.0.0.1');
    const artifactId = insertArtifact(db);
    const serviceId = createServiceNode(nodeRepo, edgeRepo, hostId, 80, 'http', artifactId);
    createEndpointNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      'GET',
      '/index',
      artifactId,
      'http://10.0.0.1:80',
    );

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'parameter_discovery')).toBe(true);
  });

  it('propose — input に observation がない場合 value_collection を提案', () => {
    const hostId = createHostNode(nodeRepo, '10.0.0.1');
    const artifactId = insertArtifact(db);
    const serviceId = createServiceNode(nodeRepo, edgeRepo, hostId, 80, 'http', artifactId);
    const endpointId = createEndpointNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      'GET',
      '/index',
      artifactId,
      'http://10.0.0.1:80',
    );
    createInputNode(nodeRepo, edgeRepo, serviceId, endpointId, 'query', 'id', artifactId);

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'value_collection')).toBe(true);
  });

  it('propose — HTTP サービスに vhost がない場合 vhost_discovery を提案', () => {
    const hostId = createHostNode(nodeRepo, '10.0.0.1');
    const artifactId = insertArtifact(db);
    createServiceNode(nodeRepo, edgeRepo, hostId, 80, 'http', artifactId);

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'vhost_discovery')).toBe(true);
  });

  it('propose — HTTP サービスに脆弱性がない場合 nuclei_scan を提案', () => {
    const hostId = createHostNode(nodeRepo, '10.0.0.1');
    const artifactId = insertArtifact(db);
    createServiceNode(nodeRepo, edgeRepo, hostId, 80, 'http', artifactId);

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'nuclei_scan')).toBe(true);
  });

  it('propose — 全て揃っている場合は空配列を返す', () => {
    const hostId = createHostNode(nodeRepo, '10.0.0.1');
    const artifactId = insertArtifact(db);
    const serviceId = createServiceNode(nodeRepo, edgeRepo, hostId, 80, 'http', artifactId);
    const endpointId = createEndpointNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      'GET',
      '/index',
      artifactId,
      'http://10.0.0.1:80',
    );
    const inputId = createInputNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      endpointId,
      'query',
      'id',
      artifactId,
    );
    createObservationNode(nodeRepo, edgeRepo, inputId, '1', artifactId);
    createVhostNode(nodeRepo, edgeRepo, hostId, 'www.example.com', artifactId);
    createVulnerabilityNode(nodeRepo, edgeRepo, serviceId, 'sqli', 'SQL Injection', artifactId);

    const actions = propose(db);

    expect(actions).toHaveLength(0);
  });

  it('propose — hostId 指定時は該当ホストのみ対象', () => {
    // host1: サービスなし
    const host1Id = createHostNode(nodeRepo, '10.0.0.1');
    // host2: 全データ揃い
    const host2Id = createHostNode(nodeRepo, '10.0.0.2');
    const artifactId = insertArtifact(db);
    const service2Id = createServiceNode(nodeRepo, edgeRepo, host2Id, 80, 'http', artifactId);
    const endpoint2Id = createEndpointNode(
      nodeRepo,
      edgeRepo,
      service2Id,
      'GET',
      '/index',
      artifactId,
      'http://10.0.0.2:80',
    );
    const input2Id = createInputNode(
      nodeRepo,
      edgeRepo,
      service2Id,
      endpoint2Id,
      'query',
      'id',
      artifactId,
    );
    createObservationNode(nodeRepo, edgeRepo, input2Id, '1', artifactId);
    createVhostNode(nodeRepo, edgeRepo, host2Id, 'www.example.com', artifactId);
    createVulnerabilityNode(nodeRepo, edgeRepo, service2Id, 'sqli', 'SQL Injection', artifactId);

    // host2 は全て揃っている → 空
    const actionsHost2 = propose(db, host2Id);
    expect(actionsHost2).toHaveLength(0);

    // host1 はサービスなし → nmap_scan
    const actionsHost1 = propose(db, host1Id);
    expect(actionsHost1.length).toBeGreaterThanOrEqual(1);
    expect(actionsHost1.some((a) => a.kind === 'nmap_scan')).toBe(true);
  });

  // =========================================================
  // エンドポイント単位の parameter_discovery
  // =========================================================

  it('propose — エンドポイント A に input あり、B に input なし → B のみ parameter_discovery 提案', () => {
    const hostId = createHostNode(nodeRepo, '10.0.0.1');
    const artifactId = insertArtifact(db);
    const serviceId = createServiceNode(nodeRepo, edgeRepo, hostId, 80, 'http', artifactId);

    // エンドポイント A: input あり
    const endpointAId = createEndpointNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      'GET',
      '/login',
      artifactId,
      'http://10.0.0.1:80',
    );
    createInputNode(nodeRepo, edgeRepo, serviceId, endpointAId, 'query', 'user', artifactId);

    // エンドポイント B: input なし
    createEndpointNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      'GET',
      '/admin',
      artifactId,
      'http://10.0.0.1:80',
    );

    // vhost + vuln を追加してノイズを減らす
    createVhostNode(nodeRepo, edgeRepo, hostId, 'www.example.com', artifactId);
    createVulnerabilityNode(nodeRepo, edgeRepo, serviceId, 'sqli', 'SQL Injection', artifactId);

    const actions = propose(db);

    // B のみ parameter_discovery が提案される
    const paramDiscovery = actions.filter((a) => a.kind === 'parameter_discovery');
    expect(paramDiscovery).toHaveLength(1);
    expect(paramDiscovery[0].description).toContain('/admin');
  });

  // =========================================================
  // value_fuzz
  // =========================================================

  it('propose — input + observation あり、vulnerability なし → value_fuzz を提案', () => {
    const hostId = createHostNode(nodeRepo, '10.0.0.1');
    const artifactId = insertArtifact(db);
    const serviceId = createServiceNode(nodeRepo, edgeRepo, hostId, 80, 'http', artifactId);
    const endpointId = createEndpointNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      'GET',
      '/search',
      artifactId,
      'http://10.0.0.1:80',
    );
    const inputId = createInputNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      endpointId,
      'query',
      'q',
      artifactId,
    );
    createObservationNode(nodeRepo, edgeRepo, inputId, 'test', artifactId);
    // vhost を追加してノイズを減らす
    createVhostNode(nodeRepo, edgeRepo, hostId, 'www.example.com', artifactId);
    // 脆弱性なし → value_fuzz が提案されるべき

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'value_fuzz')).toBe(true);
    const fuzzAction = actions.find((a) => a.kind === 'value_fuzz');
    expect(fuzzAction?.description).toContain('q');
    expect(fuzzAction?.params).toHaveProperty('inputId', inputId);
  });

  it('propose — 全脆弱性が false_positive の場合、value_fuzz と nuclei_scan を提案', () => {
    const hostId = createHostNode(nodeRepo, '10.0.0.1');
    const artifactId = insertArtifact(db);
    const serviceId = createServiceNode(nodeRepo, edgeRepo, hostId, 80, 'http', artifactId);
    const endpointId = createEndpointNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      'GET',
      '/search',
      artifactId,
      'http://10.0.0.1:80',
    );
    const inputId = createInputNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      endpointId,
      'query',
      'q',
      artifactId,
    );
    createObservationNode(nodeRepo, edgeRepo, inputId, 'test', artifactId);
    createVhostNode(nodeRepo, edgeRepo, hostId, 'www.example.com', artifactId);
    // 脆弱性を作成し、false_positive ステータスで
    createVulnerabilityNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      'sqli',
      'SQL Injection',
      artifactId,
      'false_positive',
    );

    const actions = propose(db);

    // false_positive は「脆弱性なし」として扱われるため、value_fuzz と nuclei_scan が提案される
    expect(actions.some((a) => a.kind === 'value_fuzz')).toBe(true);
    expect(actions.some((a) => a.kind === 'nuclei_scan')).toBe(true);
  });

  it('propose — input + observation + vulnerability あり → value_fuzz を提案しない', () => {
    const hostId = createHostNode(nodeRepo, '10.0.0.1');
    const artifactId = insertArtifact(db);
    const serviceId = createServiceNode(nodeRepo, edgeRepo, hostId, 80, 'http', artifactId);
    const endpointId = createEndpointNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      'GET',
      '/search',
      artifactId,
      'http://10.0.0.1:80',
    );
    const inputId = createInputNode(
      nodeRepo,
      edgeRepo,
      serviceId,
      endpointId,
      'query',
      'q',
      artifactId,
    );
    createObservationNode(nodeRepo, edgeRepo, inputId, 'test', artifactId);
    createVhostNode(nodeRepo, edgeRepo, hostId, 'www.example.com', artifactId);
    // 脆弱性あり → value_fuzz は提案されない
    createVulnerabilityNode(nodeRepo, edgeRepo, serviceId, 'sqli', 'SQL Injection', artifactId);

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'value_fuzz')).toBe(false);
  });
});
