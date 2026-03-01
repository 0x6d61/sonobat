import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import {
  GraphQueryRepository,
  type TraversalResult,
  type PathResult,
  type PresetResult,
} from '../../../src/db/repository/graph-query-repository.js';
import type { NodeKind, EdgeKind } from '../../../src/types/graph.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

function createTestDb(): InstanceType<typeof Database> {
  const db = new Database(':memory:');
  migrateDatabase(db);
  return db;
}

function insertNode(
  db: InstanceType<typeof Database>,
  id: string,
  kind: NodeKind,
  naturalKey: string,
  props: string = '{}',
): void {
  const ts = new Date().toISOString();
  db.prepare(
    'INSERT INTO nodes (id, kind, natural_key, props_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(id, kind, naturalKey, props, ts, ts);
}

function insertEdge(
  db: InstanceType<typeof Database>,
  kind: EdgeKind,
  sourceId: string,
  targetId: string,
): void {
  const id = crypto.randomUUID();
  const ts = new Date().toISOString();
  db.prepare(
    "INSERT INTO edges (id, kind, source_id, target_id, props_json, created_at) VALUES (?, ?, ?, ?, '{}', ?)",
  ).run(id, kind, sourceId, targetId, ts);
}

/**
 * テスト用グラフ構築:
 *
 *   host1 --HOST_SERVICE--> svc1 --SERVICE_ENDPOINT--> ep1 --ENDPOINT_INPUT--> in1 --INPUT_OBSERVATION--> obs1
 *                             |
 *                             +--SERVICE_OBSERVATION--> svcobs1
 *                             +--SERVICE_VULNERABILITY--> vuln1 --VULNERABILITY_CVE--> cve1
 *                             +--SERVICE_ENDPOINT--> ep2
 *                             +--SERVICE_CREDENTIAL--> cred1
 *
 *   host2 --HOST_SERVICE--> svc2 (no endpoints — used for unscanned_services)
 *                             +--SERVICE_VULNERABILITY--> vuln2
 *
 *   host1 --HOST_SERVICE--> svc3 --SERVICE_ENDPOINT--> ep3
 */
function buildTestGraph(db: InstanceType<typeof Database>): Record<string, string> {
  const ids: Record<string, string> = {
    host1: 'host-001',
    host2: 'host-002',
    svc1: 'svc-001',
    svc2: 'svc-002',
    svc3: 'svc-003',
    ep1: 'ep-001',
    ep2: 'ep-002',
    ep3: 'ep-003',
    in1: 'in-001',
    obs1: 'obs-001',
    svcobs1: 'svcobs-001',
    vuln1: 'vuln-001',
    vuln2: 'vuln-002',
    cve1: 'cve-001',
    cred1: 'cred-001',
  };

  // nodes
  insertNode(
    db,
    ids.host1,
    'host',
    'host:10.0.0.1',
    JSON.stringify({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' }),
  );
  insertNode(
    db,
    ids.host2,
    'host',
    'host:10.0.0.2',
    JSON.stringify({ authorityKind: 'IP', authority: '10.0.0.2', resolvedIpsJson: '[]' }),
  );

  insertNode(
    db,
    ids.svc1,
    'service',
    'svc:host-001:tcp:80',
    JSON.stringify({
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'confirmed',
      state: 'open',
    }),
  );
  insertNode(
    db,
    ids.svc2,
    'service',
    'svc:host-002:tcp:443',
    JSON.stringify({
      transport: 'tcp',
      port: 443,
      appProto: 'https',
      protoConfidence: 'confirmed',
      state: 'open',
    }),
  );
  insertNode(
    db,
    ids.svc3,
    'service',
    'svc:host-001:tcp:8080',
    JSON.stringify({
      transport: 'tcp',
      port: 8080,
      appProto: 'http',
      protoConfidence: 'confirmed',
      state: 'open',
    }),
  );

  insertNode(
    db,
    ids.ep1,
    'endpoint',
    'ep:svc-001:GET:/',
    JSON.stringify({ baseUri: 'http://10.0.0.1', method: 'GET', path: '/' }),
  );
  insertNode(
    db,
    ids.ep2,
    'endpoint',
    'ep:svc-001:POST:/login',
    JSON.stringify({ baseUri: 'http://10.0.0.1', method: 'POST', path: '/login' }),
  );
  insertNode(
    db,
    ids.ep3,
    'endpoint',
    'ep:svc-003:GET:/api',
    JSON.stringify({ baseUri: 'http://10.0.0.1:8080', method: 'GET', path: '/api' }),
  );

  insertNode(
    db,
    ids.in1,
    'input',
    'in:svc-001:query:q',
    JSON.stringify({ location: 'query', name: 'q' }),
  );

  insertNode(
    db,
    ids.obs1,
    'observation',
    `obs:${ids.obs1}`,
    JSON.stringify({
      rawValue: 'test',
      normValue: 'test',
      source: 'reflected',
      confidence: 'high',
      observedAt: new Date().toISOString(),
    }),
  );

  insertNode(
    db,
    ids.svcobs1,
    'svc_observation',
    `svcobs:${ids.svcobs1}`,
    JSON.stringify({ key: 'server', value: 'Apache/2.4', confidence: 'high' }),
  );

  insertNode(
    db,
    ids.vuln1,
    'vulnerability',
    `vuln:${ids.vuln1}`,
    JSON.stringify({
      vulnType: 'xss',
      title: 'Reflected XSS',
      severity: 'high',
      confidence: 'high',
      status: 'unverified',
    }),
  );
  insertNode(
    db,
    ids.vuln2,
    'vulnerability',
    `vuln:${ids.vuln2}`,
    JSON.stringify({
      vulnType: 'sqli',
      title: 'SQL Injection',
      severity: 'critical',
      confidence: 'high',
      status: 'unverified',
    }),
  );

  insertNode(
    db,
    ids.cve1,
    'cve',
    `cve:${ids.vuln1}:CVE-2024-0001`,
    JSON.stringify({ cveId: 'CVE-2024-0001', cvssScore: 9.8 }),
  );

  insertNode(
    db,
    ids.cred1,
    'credential',
    `cred:${ids.cred1}`,
    JSON.stringify({
      username: 'admin',
      secret: 'password123',
      secretType: 'password',
      source: 'bruteforce',
      confidence: 'high',
    }),
  );

  // edges
  insertEdge(db, 'HOST_SERVICE', ids.host1, ids.svc1);
  insertEdge(db, 'HOST_SERVICE', ids.host2, ids.svc2);
  insertEdge(db, 'HOST_SERVICE', ids.host1, ids.svc3);

  insertEdge(db, 'SERVICE_ENDPOINT', ids.svc1, ids.ep1);
  insertEdge(db, 'SERVICE_ENDPOINT', ids.svc1, ids.ep2);
  insertEdge(db, 'SERVICE_ENDPOINT', ids.svc3, ids.ep3);

  insertEdge(db, 'ENDPOINT_INPUT', ids.ep1, ids.in1);

  insertEdge(db, 'INPUT_OBSERVATION', ids.in1, ids.obs1);

  insertEdge(db, 'SERVICE_OBSERVATION', ids.svc1, ids.svcobs1);

  insertEdge(db, 'SERVICE_VULNERABILITY', ids.svc1, ids.vuln1);
  insertEdge(db, 'SERVICE_VULNERABILITY', ids.svc2, ids.vuln2);

  insertEdge(db, 'VULNERABILITY_CVE', ids.vuln1, ids.cve1);

  insertEdge(db, 'SERVICE_CREDENTIAL', ids.svc1, ids.cred1);

  return ids;
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('GraphQueryRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: GraphQueryRepository;
  let ids: Record<string, string>;

  beforeEach(() => {
    db = createTestDb();
    ids = buildTestGraph(db);
    repo = new GraphQueryRepository(db);
  });

  // =========================================================================
  // traverse
  // =========================================================================

  describe('traverse', () => {
    it('depth=1 で host から直接の子ノード(service)のみ返す', () => {
      const results: TraversalResult[] = repo.traverse(ids.host1, 1);

      const nodeIds = results.map((r) => r.node.id);
      // host1 -> svc1, svc3
      expect(nodeIds).toContain(ids.svc1);
      expect(nodeIds).toContain(ids.svc3);
      expect(nodeIds).toHaveLength(2);

      // 全結果の depth が 1 であること
      for (const r of results) {
        expect(r.depth).toBe(1);
      }
    });

    it('depth=2 で host から service + endpoint を返す', () => {
      const results: TraversalResult[] = repo.traverse(ids.host1, 2);

      const nodeIds = results.map((r) => r.node.id);
      // depth 1: svc1, svc3
      expect(nodeIds).toContain(ids.svc1);
      expect(nodeIds).toContain(ids.svc3);
      // depth 2: ep1, ep2, ep3, svcobs1, vuln1, cred1
      expect(nodeIds).toContain(ids.ep1);
      expect(nodeIds).toContain(ids.ep2);
      expect(nodeIds).toContain(ids.ep3);
      expect(nodeIds).toContain(ids.svcobs1);
      expect(nodeIds).toContain(ids.vuln1);
      expect(nodeIds).toContain(ids.cred1);

      // depth 確認
      const svc1Result = results.find((r) => r.node.id === ids.svc1);
      expect(svc1Result?.depth).toBe(1);

      const ep1Result = results.find((r) => r.node.id === ids.ep1);
      expect(ep1Result?.depth).toBe(2);
    });

    it('depth を指定しない場合、デフォルトで全ての到達可能なノードを返す', () => {
      const results: TraversalResult[] = repo.traverse(ids.host1);

      const nodeIds = results.map((r) => r.node.id);
      // host1 から到達可能な全ノード
      expect(nodeIds).toContain(ids.svc1);
      expect(nodeIds).toContain(ids.svc3);
      expect(nodeIds).toContain(ids.ep1);
      expect(nodeIds).toContain(ids.ep2);
      expect(nodeIds).toContain(ids.ep3);
      expect(nodeIds).toContain(ids.in1);
      expect(nodeIds).toContain(ids.obs1);
      expect(nodeIds).toContain(ids.svcobs1);
      expect(nodeIds).toContain(ids.vuln1);
      expect(nodeIds).toContain(ids.cve1);
      expect(nodeIds).toContain(ids.cred1);
      // host2, svc2, vuln2 は到達不可
      expect(nodeIds).not.toContain(ids.host2);
      expect(nodeIds).not.toContain(ids.svc2);
      expect(nodeIds).not.toContain(ids.vuln2);
    });

    it('edgeKinds フィルタで指定したエッジ種別のみ辿る', () => {
      const results: TraversalResult[] = repo.traverse(ids.host1, undefined, [
        'HOST_SERVICE',
        'SERVICE_ENDPOINT',
      ]);

      const nodeIds = results.map((r) => r.node.id);
      // HOST_SERVICE + SERVICE_ENDPOINT のみ
      expect(nodeIds).toContain(ids.svc1);
      expect(nodeIds).toContain(ids.svc3);
      expect(nodeIds).toContain(ids.ep1);
      expect(nodeIds).toContain(ids.ep2);
      expect(nodeIds).toContain(ids.ep3);
      // SERVICE_VULNERABILITY 等は辿らない
      expect(nodeIds).not.toContain(ids.vuln1);
      expect(nodeIds).not.toContain(ids.svcobs1);
      expect(nodeIds).not.toContain(ids.cred1);
    });

    it('path にスタートノードから当該ノードまでの ID 列が含まれる', () => {
      const results: TraversalResult[] = repo.traverse(ids.host1, 3);

      const in1Result = results.find((r) => r.node.id === ids.in1);
      expect(in1Result).toBeDefined();
      expect(in1Result!.depth).toBe(3);
      expect(in1Result!.path).toEqual([ids.host1, ids.svc1, ids.ep1, ids.in1]);
    });

    it('存在しないノード ID の場合、空配列を返す', () => {
      const results = repo.traverse('nonexistent-id');
      expect(results).toEqual([]);
    });
  });

  // =========================================================================
  // reachableFrom
  // =========================================================================

  describe('reachableFrom', () => {
    it('開始ノードから到達可能な全ノードを返す', () => {
      const nodes = repo.reachableFrom(ids.host1);

      const nodeIds = nodes.map((n) => n.id);
      expect(nodeIds).toContain(ids.svc1);
      expect(nodeIds).toContain(ids.svc3);
      expect(nodeIds).toContain(ids.ep1);
      expect(nodeIds).toContain(ids.vuln1);
      expect(nodeIds).toContain(ids.cve1);
      // host2 系は到達不可
      expect(nodeIds).not.toContain(ids.host2);
      expect(nodeIds).not.toContain(ids.svc2);
    });

    it('targetKind で絞り込みできる', () => {
      const vulns = repo.reachableFrom(ids.host1, 'vulnerability');

      expect(vulns).toHaveLength(1);
      expect(vulns[0].id).toBe(ids.vuln1);
      expect(vulns[0].kind).toBe('vulnerability');
    });

    it('到達可能なノードがない場合、空配列を返す', () => {
      // obs1 は末端ノード（outgoing edge なし）
      const nodes = repo.reachableFrom(ids.obs1);
      expect(nodes).toEqual([]);
    });

    it('targetKind に一致するノードがない場合、空配列を返す', () => {
      // host2 から credential は到達不可
      const creds = repo.reachableFrom(ids.host2, 'credential');
      expect(creds).toEqual([]);
    });
  });

  // =========================================================================
  // shortestPath
  // =========================================================================

  describe('shortestPath', () => {
    it('2ノード間の最短パスを返す', () => {
      const result: PathResult | undefined = repo.shortestPath(ids.host1, ids.cve1);

      expect(result).toBeDefined();
      // host1 -> svc1 -> vuln1 -> cve1
      expect(result!.nodes).toHaveLength(4);
      expect(result!.nodes[0].id).toBe(ids.host1);
      expect(result!.nodes[result!.nodes.length - 1].id).toBe(ids.cve1);
      expect(result!.length).toBe(3);
      expect(result!.edges).toHaveLength(3);
    });

    it('直接接続のパスを返す', () => {
      const result = repo.shortestPath(ids.host1, ids.svc1);

      expect(result).toBeDefined();
      expect(result!.nodes).toHaveLength(2);
      expect(result!.nodes[0].id).toBe(ids.host1);
      expect(result!.nodes[1].id).toBe(ids.svc1);
      expect(result!.length).toBe(1);
      expect(result!.edges).toHaveLength(1);
      expect(result!.edges[0].kind).toBe('HOST_SERVICE');
    });

    it('パスが存在しない場合 undefined を返す', () => {
      // host1 -> host2 はパスなし
      const result = repo.shortestPath(ids.host1, ids.host2);
      expect(result).toBeUndefined();
    });

    it('同一ノードの場合、長さ0のパスを返す', () => {
      const result = repo.shortestPath(ids.host1, ids.host1);

      expect(result).toBeDefined();
      expect(result!.nodes).toHaveLength(1);
      expect(result!.nodes[0].id).toBe(ids.host1);
      expect(result!.length).toBe(0);
      expect(result!.edges).toHaveLength(0);
    });
  });

  // =========================================================================
  // runPreset
  // =========================================================================

  describe('runPreset', () => {
    describe('attack_surface', () => {
      it('host から endpoint + input への完全パスを返す', () => {
        const results: PresetResult = repo.runPreset('attack_surface');

        // 少なくとも host1 -> svc1 -> ep1 -> in1 のパスが含まれる
        expect(results.length).toBeGreaterThanOrEqual(1);

        const withInput = results.filter((r) => r.inputId !== null && r.inputId !== undefined);
        expect(withInput.length).toBeGreaterThanOrEqual(1);

        // host, service, endpoint の情報が含まれている
        const row = results.find((r) => r.inputId === ids.in1);
        expect(row).toBeDefined();
        expect(row!.hostId).toBe(ids.host1);
        expect(row!.serviceId).toBe(ids.svc1);
        expect(row!.endpointId).toBe(ids.ep1);
      });
    });

    describe('critical_vulns', () => {
      it('severity が critical/high の脆弱性をホスト情報付きで返す', () => {
        const results: PresetResult = repo.runPreset('critical_vulns');

        // vuln1 (high) と vuln2 (critical) の両方が含まれる
        expect(results.length).toBe(2);

        const severities = results.map((r) => r.severity);
        expect(severities).toContain('high');
        expect(severities).toContain('critical');

        // host 情報が付いている
        const vuln1Row = results.find((r) => r.vulnId === ids.vuln1);
        expect(vuln1Row).toBeDefined();
        expect(vuln1Row!.hostId).toBe(ids.host1);
      });
    });

    describe('credential_exposure', () => {
      it('service -> credential のマッピングを返す', () => {
        const results: PresetResult = repo.runPreset('credential_exposure');

        expect(results.length).toBe(1);
        expect(results[0].serviceId).toBe(ids.svc1);
        expect(results[0].credentialId).toBe(ids.cred1);
      });
    });

    describe('unscanned_services', () => {
      it('endpoint が 0 件のサービスを返す', () => {
        const results: PresetResult = repo.runPreset('unscanned_services');

        // svc2 のみ endpoint なし
        expect(results.length).toBe(1);
        expect(results[0].serviceId).toBe(ids.svc2);
      });
    });

    describe('vuln_by_host', () => {
      it('ホスト別脆弱性カウントを返す', () => {
        const results: PresetResult = repo.runPreset('vuln_by_host');

        expect(results.length).toBe(2);

        const host1Row = results.find((r) => r.hostId === ids.host1);
        expect(host1Row).toBeDefined();
        expect(host1Row!.vulnCount).toBe(1);

        const host2Row = results.find((r) => r.hostId === ids.host2);
        expect(host2Row).toBeDefined();
        expect(host2Row!.vulnCount).toBe(1);
      });
    });

    describe('reachable_services', () => {
      it('host から到達可能な全サービスを返す', () => {
        const results: PresetResult = repo.runPreset('reachable_services', {
          hostId: ids.host1,
        });

        const serviceIds = results.map((r) => r.serviceId);
        expect(serviceIds).toContain(ids.svc1);
        expect(serviceIds).toContain(ids.svc3);
        expect(serviceIds).not.toContain(ids.svc2);
        expect(results.length).toBe(2);
      });
    });

    it('不明なプリセットパターンでエラーを投げる', () => {
      expect(() => repo.runPreset('unknown_pattern')).toThrow(
        'Unknown preset pattern: unknown_pattern',
      );
    });
  });
});
