/**
 * sonobat — v4 Migration tests
 *
 * v3 DB → v4 (graph-native) マイグレーションの検証。
 * - nodes/edges テーブルが作成される
 * - 旧テーブルのデータが正しく移行される
 * - 旧テーブルが DROP される
 */

import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';

// v3 までのスキーマを構築するためにマイグレーション部品をインポート
import v0 from '../../../src/db/migrations/v0.js';
import v1 from '../../../src/db/migrations/v1.js';
import v2 from '../../../src/db/migrations/v2.js';
import v3 from '../../../src/db/migrations/v3.js';
import v4 from '../../../src/db/migrations/v4.js';

function uuid(): string {
  return crypto.randomUUID();
}

function now(): string {
  return new Date().toISOString();
}

function tableNames(db: InstanceType<typeof Database>): string[] {
  const rows = db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    .all() as Array<{ name: string }>;
  return rows.map((r) => r.name).sort();
}

function indexNames(db: InstanceType<typeof Database>): string[] {
  const rows = db
    .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")
    .all() as Array<{ name: string }>;
  return rows.map((r) => r.name).sort();
}

/**
 * v3 状態のDBを構築し、テストデータを挿入するヘルパー。
 * 返り値に各エンティティのIDを含む。
 */
function setupV3DbWithData(db: InstanceType<typeof Database>): {
  artifactId: string;
  hostId: string;
  serviceId: string;
  endpointId: string;
  inputId: string;
  observationId: string;
  credentialId: string;
  vulnId: string;
  cveRowId: string;
  vhostId: string;
  svcObsId: string;
  epInputId: string;
} {
  db.pragma('foreign_keys = ON');

  // v0 → v1 → v2 → v3 を順次実行
  v0.up(db);
  v1.up(db);
  v2.up(db);
  v3.up(db);

  const ts = now();

  // artifact
  const artifactId = uuid();
  db.prepare(
    `INSERT INTO artifacts (id, tool, kind, path, captured_at)
     VALUES (?, 'nmap', 'tool_output', '/tmp/scan.xml', ?)`,
  ).run(artifactId, ts);

  // host
  const hostId = uuid();
  db.prepare(
    `INSERT INTO hosts (id, authority_kind, authority, resolved_ips_json, created_at, updated_at)
     VALUES (?, 'IP', '192.168.1.1', '["192.168.1.1"]', ?, ?)`,
  ).run(hostId, ts, ts);

  // vhost
  const vhostId = uuid();
  db.prepare(
    `INSERT INTO vhosts (id, host_id, hostname, source, evidence_artifact_id, created_at)
     VALUES (?, ?, 'www.example.com', 'nmap', ?, ?)`,
  ).run(vhostId, hostId, artifactId, ts);

  // service
  const serviceId = uuid();
  db.prepare(
    `INSERT INTO services (id, host_id, transport, port, app_proto, proto_confidence, banner, product, version, state, evidence_artifact_id, created_at, updated_at)
     VALUES (?, ?, 'tcp', 80, 'http', 'high', 'nginx', 'nginx', '1.21', 'open', ?, ?, ?)`,
  ).run(serviceId, hostId, artifactId, ts, ts);

  // service_observation
  const svcObsId = uuid();
  db.prepare(
    `INSERT INTO service_observations (id, service_id, key, value, confidence, evidence_artifact_id, created_at)
     VALUES (?, ?, 'os', 'Linux', 'high', ?, ?)`,
  ).run(svcObsId, serviceId, artifactId, ts);

  // http_endpoint
  const endpointId = uuid();
  db.prepare(
    `INSERT INTO http_endpoints (id, service_id, vhost_id, base_uri, method, path, status_code, evidence_artifact_id, created_at)
     VALUES (?, ?, ?, 'http://192.168.1.1:80', 'GET', '/admin', 200, ?, ?)`,
  ).run(endpointId, serviceId, vhostId, artifactId, ts);

  // input
  const inputId = uuid();
  db.prepare(
    `INSERT INTO inputs (id, service_id, location, name, created_at, updated_at)
     VALUES (?, ?, 'query', 'id', ?, ?)`,
  ).run(inputId, serviceId, ts, ts);

  // endpoint_input
  const epInputId = uuid();
  db.prepare(
    `INSERT INTO endpoint_inputs (id, endpoint_id, input_id, evidence_artifact_id, created_at)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(epInputId, endpointId, inputId, artifactId, ts);

  // observation
  const observationId = uuid();
  db.prepare(
    `INSERT INTO observations (id, input_id, raw_value, norm_value, source, confidence, evidence_artifact_id, observed_at)
     VALUES (?, ?, 'test', 'test', 'ffuf_url', 'high', ?, ?)`,
  ).run(observationId, inputId, artifactId, ts);

  // credential
  const credentialId = uuid();
  db.prepare(
    `INSERT INTO credentials (id, service_id, endpoint_id, username, secret, secret_type, source, confidence, evidence_artifact_id, created_at)
     VALUES (?, ?, ?, 'admin', 'password123', 'password', 'default', 'high', ?, ?)`,
  ).run(credentialId, serviceId, endpointId, artifactId, ts);

  // vulnerability
  const vulnId = uuid();
  db.prepare(
    `INSERT INTO vulnerabilities (id, service_id, endpoint_id, vuln_type, title, description, severity, confidence, status, evidence_artifact_id, created_at)
     VALUES (?, ?, ?, 'sqli', 'SQL Injection', 'Found SQL injection', 'critical', 'high', 'confirmed', ?, ?)`,
  ).run(vulnId, serviceId, endpointId, artifactId, ts);

  // cve
  const cveRowId = uuid();
  db.prepare(
    `INSERT INTO cves (id, vulnerability_id, cve_id, description, cvss_score, created_at)
     VALUES (?, ?, 'CVE-2021-44228', 'Log4Shell', 10.0, ?)`,
  ).run(cveRowId, vulnId, ts);

  return {
    artifactId,
    hostId,
    serviceId,
    endpointId,
    inputId,
    observationId,
    credentialId,
    vulnId,
    cveRowId,
    vhostId,
    svcObsId,
    epInputId,
  };
}

// ============================================================
// テスト
// ============================================================

describe('v4 migration', () => {
  let db: InstanceType<typeof Database>;

  beforeEach(() => {
    db = new Database(':memory:');
  });

  it('nodes テーブルが作成される', () => {
    setupV3DbWithData(db);
    v4.up(db);

    const tables = tableNames(db);
    expect(tables).toContain('nodes');
  });

  it('edges テーブルが作成される', () => {
    setupV3DbWithData(db);
    v4.up(db);

    const tables = tableNames(db);
    expect(tables).toContain('edges');
  });

  it('旧エンティティテーブルが DROP される', () => {
    setupV3DbWithData(db);
    v4.up(db);

    const tables = tableNames(db);
    const droppedTables = [
      'hosts',
      'vhosts',
      'services',
      'service_observations',
      'http_endpoints',
      'inputs',
      'endpoint_inputs',
      'observations',
      'credentials',
      'vulnerabilities',
      'cves',
      'datalog_rules',
    ];
    for (const t of droppedTables) {
      expect(tables).not.toContain(t);
    }
  });

  it('残存テーブル (scans, artifacts, technique_docs) は残る', () => {
    setupV3DbWithData(db);
    v4.up(db);

    const tables = tableNames(db);
    expect(tables).toContain('scans');
    expect(tables).toContain('artifacts');
    expect(tables).toContain('technique_docs');
  });

  it('インデックスが作成される', () => {
    setupV3DbWithData(db);
    v4.up(db);

    const indexes = indexNames(db);
    expect(indexes).toContain('idx_nodes_kind');
    expect(indexes).toContain('idx_nodes_evidence');
    expect(indexes).toContain('idx_edges_source');
    expect(indexes).toContain('idx_edges_target');
    expect(indexes).toContain('idx_edges_kind');
  });

  it('hosts が node (kind="host") に移行される', () => {
    const { hostId } = setupV3DbWithData(db);
    v4.up(db);

    const node = db.prepare(`SELECT * FROM nodes WHERE id = ?`).get(hostId) as Record<
      string,
      unknown
    >;

    expect(node).toBeDefined();
    expect(node.kind).toBe('host');
    expect(node.natural_key).toBe('host:192.168.1.1');

    const props = JSON.parse(node.props_json as string);
    expect(props.authorityKind).toBe('IP');
    expect(props.authority).toBe('192.168.1.1');
    expect(props.resolvedIpsJson).toBe('["192.168.1.1"]');
  });

  it('services が node (kind="service") + edge (HOST_SERVICE) に移行される', () => {
    const { hostId, serviceId } = setupV3DbWithData(db);
    v4.up(db);

    const node = db.prepare(`SELECT * FROM nodes WHERE id = ?`).get(serviceId) as Record<
      string,
      unknown
    >;

    expect(node).toBeDefined();
    expect(node.kind).toBe('service');
    expect(node.natural_key).toBe(`svc:${hostId}:tcp:80`);

    const props = JSON.parse(node.props_json as string);
    expect(props.transport).toBe('tcp');
    expect(props.port).toBe(80);
    expect(props.appProto).toBe('http');
    expect(props.state).toBe('open');

    // HOST_SERVICE edge
    const edge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'HOST_SERVICE' AND source_id = ? AND target_id = ?`,
      )
      .get(hostId, serviceId) as Record<string, unknown>;
    expect(edge).toBeDefined();
  });

  it('http_endpoints が node (kind="endpoint") + edge (SERVICE_ENDPOINT) に移行される', () => {
    const { serviceId, endpointId } = setupV3DbWithData(db);
    v4.up(db);

    const node = db.prepare(`SELECT * FROM nodes WHERE id = ?`).get(endpointId) as Record<
      string,
      unknown
    >;

    expect(node).toBeDefined();
    expect(node.kind).toBe('endpoint');
    expect(node.natural_key).toBe(`ep:${serviceId}:GET:/admin`);

    // SERVICE_ENDPOINT edge
    const edge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'SERVICE_ENDPOINT' AND source_id = ? AND target_id = ?`,
      )
      .get(serviceId, endpointId) as Record<string, unknown>;
    expect(edge).toBeDefined();
  });

  it('vhost_id がある endpoint には VHOST_ENDPOINT edge も作成される', () => {
    const { vhostId, endpointId } = setupV3DbWithData(db);
    v4.up(db);

    const edge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'VHOST_ENDPOINT' AND source_id = ? AND target_id = ?`,
      )
      .get(vhostId, endpointId) as Record<string, unknown>;
    expect(edge).toBeDefined();
  });

  it('inputs が node (kind="input") + edge (SERVICE_INPUT) に移行される', () => {
    const { serviceId, inputId } = setupV3DbWithData(db);
    v4.up(db);

    const node = db.prepare(`SELECT * FROM nodes WHERE id = ?`).get(inputId) as Record<
      string,
      unknown
    >;

    expect(node).toBeDefined();
    expect(node.kind).toBe('input');
    expect(node.natural_key).toBe(`in:${serviceId}:query:id`);

    // SERVICE_INPUT edge
    const edge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'SERVICE_INPUT' AND source_id = ? AND target_id = ?`,
      )
      .get(serviceId, inputId) as Record<string, unknown>;
    expect(edge).toBeDefined();
  });

  it('endpoint_inputs が edge (ENDPOINT_INPUT) に移行される', () => {
    const { endpointId, inputId } = setupV3DbWithData(db);
    v4.up(db);

    const edge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'ENDPOINT_INPUT' AND source_id = ? AND target_id = ?`,
      )
      .get(endpointId, inputId) as Record<string, unknown>;
    expect(edge).toBeDefined();
  });

  it('observations が node (kind="observation") + edge (INPUT_OBSERVATION) に移行される', () => {
    const { inputId, observationId } = setupV3DbWithData(db);
    v4.up(db);

    const node = db.prepare(`SELECT * FROM nodes WHERE id = ?`).get(observationId) as Record<
      string,
      unknown
    >;

    expect(node).toBeDefined();
    expect(node.kind).toBe('observation');

    const props = JSON.parse(node.props_json as string);
    expect(props.rawValue).toBe('test');
    expect(props.source).toBe('ffuf_url');

    // INPUT_OBSERVATION edge
    const edge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'INPUT_OBSERVATION' AND source_id = ? AND target_id = ?`,
      )
      .get(inputId, observationId) as Record<string, unknown>;
    expect(edge).toBeDefined();
  });

  it('credentials が node (kind="credential") + edges に移行される', () => {
    const { serviceId, endpointId, credentialId } = setupV3DbWithData(db);
    v4.up(db);

    const node = db.prepare(`SELECT * FROM nodes WHERE id = ?`).get(credentialId) as Record<
      string,
      unknown
    >;

    expect(node).toBeDefined();
    expect(node.kind).toBe('credential');

    const props = JSON.parse(node.props_json as string);
    expect(props.username).toBe('admin');
    expect(props.secretType).toBe('password');

    // SERVICE_CREDENTIAL edge
    const svcEdge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'SERVICE_CREDENTIAL' AND source_id = ? AND target_id = ?`,
      )
      .get(serviceId, credentialId) as Record<string, unknown>;
    expect(svcEdge).toBeDefined();

    // ENDPOINT_CREDENTIAL edge (endpoint_id があるので)
    const epEdge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'ENDPOINT_CREDENTIAL' AND source_id = ? AND target_id = ?`,
      )
      .get(endpointId, credentialId) as Record<string, unknown>;
    expect(epEdge).toBeDefined();
  });

  it('vulnerabilities が node (kind="vulnerability") + edges に移行される', () => {
    const { serviceId, endpointId, vulnId } = setupV3DbWithData(db);
    v4.up(db);

    const node = db.prepare(`SELECT * FROM nodes WHERE id = ?`).get(vulnId) as Record<
      string,
      unknown
    >;

    expect(node).toBeDefined();
    expect(node.kind).toBe('vulnerability');

    const props = JSON.parse(node.props_json as string);
    expect(props.vulnType).toBe('sqli');
    expect(props.title).toBe('SQL Injection');
    expect(props.severity).toBe('critical');
    expect(props.status).toBe('confirmed');

    // SERVICE_VULNERABILITY edge
    const svcEdge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'SERVICE_VULNERABILITY' AND source_id = ? AND target_id = ?`,
      )
      .get(serviceId, vulnId) as Record<string, unknown>;
    expect(svcEdge).toBeDefined();

    // ENDPOINT_VULNERABILITY edge
    const epEdge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'ENDPOINT_VULNERABILITY' AND source_id = ? AND target_id = ?`,
      )
      .get(endpointId, vulnId) as Record<string, unknown>;
    expect(epEdge).toBeDefined();
  });

  it('cves が node (kind="cve") + edge (VULNERABILITY_CVE) に移行される', () => {
    const { vulnId, cveRowId } = setupV3DbWithData(db);
    v4.up(db);

    const node = db.prepare(`SELECT * FROM nodes WHERE id = ?`).get(cveRowId) as Record<
      string,
      unknown
    >;

    expect(node).toBeDefined();
    expect(node.kind).toBe('cve');
    expect(node.natural_key).toBe(`cve:${vulnId}:CVE-2021-44228`);

    const props = JSON.parse(node.props_json as string);
    expect(props.cveId).toBe('CVE-2021-44228');
    expect(props.cvssScore).toBe(10.0);

    // VULNERABILITY_CVE edge
    const edge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'VULNERABILITY_CVE' AND source_id = ? AND target_id = ?`,
      )
      .get(vulnId, cveRowId) as Record<string, unknown>;
    expect(edge).toBeDefined();
  });

  it('vhosts が node (kind="vhost") + edge (HOST_VHOST) に移行される', () => {
    const { hostId, vhostId } = setupV3DbWithData(db);
    v4.up(db);

    const node = db.prepare(`SELECT * FROM nodes WHERE id = ?`).get(vhostId) as Record<
      string,
      unknown
    >;

    expect(node).toBeDefined();
    expect(node.kind).toBe('vhost');
    expect(node.natural_key).toBe(`vhost:${hostId}:www.example.com`);

    const props = JSON.parse(node.props_json as string);
    expect(props.hostname).toBe('www.example.com');

    // HOST_VHOST edge
    const edge = db
      .prepare(`SELECT * FROM edges WHERE kind = 'HOST_VHOST' AND source_id = ? AND target_id = ?`)
      .get(hostId, vhostId) as Record<string, unknown>;
    expect(edge).toBeDefined();
  });

  it('service_observations が node (kind="svc_observation") + edge (SERVICE_OBSERVATION) に移行される', () => {
    const { serviceId, svcObsId } = setupV3DbWithData(db);
    v4.up(db);

    const node = db.prepare(`SELECT * FROM nodes WHERE id = ?`).get(svcObsId) as Record<
      string,
      unknown
    >;

    expect(node).toBeDefined();
    expect(node.kind).toBe('svc_observation');

    const props = JSON.parse(node.props_json as string);
    expect(props.key).toBe('os');
    expect(props.value).toBe('Linux');

    // SERVICE_OBSERVATION edge
    const edge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'SERVICE_OBSERVATION' AND source_id = ? AND target_id = ?`,
      )
      .get(serviceId, svcObsId) as Record<string, unknown>;
    expect(edge).toBeDefined();
  });

  it('evidence_artifact_id が正しく引き継がれる', () => {
    const { artifactId, serviceId } = setupV3DbWithData(db);
    v4.up(db);

    const node = db
      .prepare(`SELECT evidence_artifact_id FROM nodes WHERE id = ?`)
      .get(serviceId) as Record<string, unknown>;

    expect(node.evidence_artifact_id).toBe(artifactId);
  });

  it('nodes の UNIQUE(natural_key) 制約が機能する', () => {
    setupV3DbWithData(db);
    v4.up(db);

    const ts = now();
    expect(() => {
      db.prepare(
        `INSERT INTO nodes (id, kind, natural_key, props_json, created_at, updated_at)
         VALUES (?, 'host', 'host:192.168.1.1', '{}', ?, ?)`,
      ).run(uuid(), ts, ts);
    }).toThrow(/UNIQUE/);
  });

  it('edges の UNIQUE(kind, source_id, target_id) 制約が機能する', () => {
    const { hostId, serviceId } = setupV3DbWithData(db);
    v4.up(db);

    const ts = now();
    expect(() => {
      db.prepare(
        `INSERT INTO edges (id, kind, source_id, target_id, props_json, created_at)
         VALUES (?, 'HOST_SERVICE', ?, ?, '{}', ?)`,
      ).run(uuid(), hostId, serviceId, ts);
    }).toThrow(/UNIQUE/);
  });

  it('CASCADE 削除: node 削除で関連 edge も削除される', () => {
    const { hostId } = setupV3DbWithData(db);
    v4.up(db);

    // host ノードを削除
    db.prepare('DELETE FROM nodes WHERE id = ?').run(hostId);

    // HOST_SERVICE edge も CASCADE で消えること
    const edges = db
      .prepare(`SELECT COUNT(*) AS cnt FROM edges WHERE source_id = ? OR target_id = ?`)
      .get(hostId, hostId) as { cnt: number };
    expect(edges.cnt).toBe(0);
  });

  it('空の DB（テーブルはあるがデータなし）でも v4 が正常に実行される', () => {
    const db2 = new Database(':memory:');
    db2.pragma('foreign_keys = ON');
    v0.up(db2);
    v1.up(db2);
    v2.up(db2);
    v3.up(db2);

    // データなしで v4 実行
    expect(() => v4.up(db2)).not.toThrow();

    const tables = tableNames(db2);
    expect(tables).toContain('nodes');
    expect(tables).toContain('edges');
    expect(tables).not.toContain('hosts');
  });

  it('移行後のノード数とエッジ数が正しい', () => {
    setupV3DbWithData(db);
    v4.up(db);

    // ノード数: host(1) + vhost(1) + service(1) + endpoint(1) + input(1) +
    //           observation(1) + credential(1) + vulnerability(1) + cve(1) + svc_observation(1) = 10
    const nodeCount = (db.prepare('SELECT COUNT(*) AS cnt FROM nodes').get() as { cnt: number })
      .cnt;
    expect(nodeCount).toBe(10);

    // エッジ数:
    // HOST_SERVICE(1) + HOST_VHOST(1) + SERVICE_ENDPOINT(1) + VHOST_ENDPOINT(1) +
    // SERVICE_INPUT(1) + ENDPOINT_INPUT(1) + INPUT_OBSERVATION(1) +
    // SERVICE_CREDENTIAL(1) + ENDPOINT_CREDENTIAL(1) +
    // SERVICE_VULNERABILITY(1) + ENDPOINT_VULNERABILITY(1) +
    // VULNERABILITY_CVE(1) + SERVICE_OBSERVATION(1) = 13
    const edgeCount = (db.prepare('SELECT COUNT(*) AS cnt FROM edges').get() as { cnt: number })
      .cnt;
    expect(edgeCount).toBe(13);
  });
});
