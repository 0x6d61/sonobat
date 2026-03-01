import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../src/db/migrate.js';
import crypto from 'node:crypto';
import { NodeRepository } from '../../src/db/repository/node-repository.js';
import { EdgeRepository } from '../../src/db/repository/edge-repository.js';
import { normalize } from '../../src/engine/normalizer.js';
import type { NormalizeResult } from '../../src/engine/normalizer.js';
import { emptyParseResult } from '../../src/types/parser.js';
import type { ParseResult } from '../../src/types/parser.js';

// ---------------------------------------------------------------------------
// ヘルパー: propsJson から型安全にパースする
// ---------------------------------------------------------------------------

function parseProps<T = Record<string, unknown>>(propsJson: string): T {
  return JSON.parse(propsJson) as T;
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

/** Direct SQL helper to create an artifact (ArtifactRepository is removed) */
function createArtifact(db: InstanceType<typeof Database>, tool: string, path: string): string {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(
    'INSERT INTO artifacts (id, tool, kind, path, captured_at) VALUES (?, ?, ?, ?, ?)',
  ).run(id, tool, 'tool_output', path, now);
  return id;
}

describe('normalize', () => {
  let db: InstanceType<typeof Database>;
  let nodeRepo: NodeRepository;
  let edgeRepo: EdgeRepository;
  let artifactId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);

    nodeRepo = new NodeRepository(db);
    edgeRepo = new EdgeRepository(db);

    // FK 制約を満たすためにアーティファクトレコードを事前作成
    artifactId = createArtifact(db, 'nmap', '/tmp/scan-output.xml');
  });

  // -----------------------------------------------------------------------
  // 1. nmap 結果を正規化する（hosts + services + serviceObservations）
  // -----------------------------------------------------------------------

  it('nmap 結果を正規化する（hosts + services + serviceObservations）', () => {
    const parseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [{ authority: '10.0.0.1', authorityKind: 'IP' }],
      services: [
        {
          hostAuthority: '10.0.0.1',
          transport: 'tcp',
          port: 22,
          appProto: 'ssh',
          protoConfidence: 'high',
          state: 'open',
        },
        {
          hostAuthority: '10.0.0.1',
          transport: 'tcp',
          port: 80,
          appProto: 'http',
          protoConfidence: 'high',
          state: 'open',
        },
      ],
      serviceObservations: [
        {
          hostAuthority: '10.0.0.1',
          transport: 'tcp',
          port: 22,
          key: 'os',
          value: 'Linux 5.4',
          confidence: 'medium',
        },
      ],
    };

    const result: NormalizeResult = normalize(db, artifactId, parseResult);

    // NormalizeResult の検証
    expect(result.hostsCreated).toBe(1);
    expect(result.servicesCreated).toBe(2);
    expect(result.serviceObservationsCreated).toBe(1);
    expect(result.httpEndpointsCreated).toBe(0);
    expect(result.inputsCreated).toBe(0);
    expect(result.endpointInputsCreated).toBe(0);
    expect(result.observationsCreated).toBe(0);
    expect(result.vulnerabilitiesCreated).toBe(0);
    expect(result.cvesCreated).toBe(0);

    // DB 状態の検証 — host ノード
    const hosts = nodeRepo.findByKind('host');
    expect(hosts).toHaveLength(1);
    const hostProps = parseProps<{ authority: string; authorityKind: string }>(hosts[0].propsJson);
    expect(hostProps.authority).toBe('10.0.0.1');
    expect(hostProps.authorityKind).toBe('IP');

    // DB 状態の検証 — service ノード（HOST_SERVICE edge 経由）
    const hostServiceEdges = edgeRepo.findBySource(hosts[0].id, 'HOST_SERVICE');
    expect(hostServiceEdges).toHaveLength(2);

    const serviceNodes = hostServiceEdges.map((e) => nodeRepo.findById(e.targetId)!);
    const ports = serviceNodes
      .map((s) => parseProps<{ port: number }>(s.propsJson).port)
      .sort((a, b) => a - b);
    expect(ports).toEqual([22, 80]);

    // DB 状態の検証 — svc_observation ノード（SERVICE_OBSERVATION edge 経由）
    const sshService = serviceNodes.find(
      (s) => parseProps<{ port: number }>(s.propsJson).port === 22,
    );
    expect(sshService).toBeDefined();

    const svcObsEdges = edgeRepo.findBySource(sshService!.id, 'SERVICE_OBSERVATION');
    expect(svcObsEdges).toHaveLength(1);

    const obsNode = nodeRepo.findById(svcObsEdges[0].targetId)!;
    const obsProps = parseProps<{ key: string; value: string }>(obsNode.propsJson);
    expect(obsProps.key).toBe('os');
    expect(obsProps.value).toBe('Linux 5.4');
  });

  // -----------------------------------------------------------------------
  // 2. ffuf 結果を正規化する（endpoints + inputs + observations + endpointInputs）
  // -----------------------------------------------------------------------

  it('ffuf 結果を正規化する（endpoints + inputs + observations + endpointInputs）', () => {
    const parseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [{ authority: '10.0.0.1', authorityKind: 'IP' }],
      services: [
        {
          hostAuthority: '10.0.0.1',
          transport: 'tcp',
          port: 80,
          appProto: 'http',
          protoConfidence: 'high',
          state: 'open',
        },
      ],
      httpEndpoints: [
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          baseUri: 'http://10.0.0.1:80',
          method: 'GET',
          path: '/admin',
          statusCode: 200,
        },
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          baseUri: 'http://10.0.0.1:80',
          method: 'GET',
          path: '/login',
          statusCode: 200,
        },
      ],
      inputs: [
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          location: 'query',
          name: 'q',
        },
      ],
      endpointInputs: [
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          method: 'GET',
          path: '/admin',
          inputLocation: 'query',
          inputName: 'q',
        },
      ],
      observations: [
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          inputLocation: 'query',
          inputName: 'q',
          rawValue: 'admin',
          normValue: 'admin',
          source: 'ffuf',
          confidence: 'high',
        },
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          inputLocation: 'query',
          inputName: 'q',
          rawValue: 'test',
          normValue: 'test',
          source: 'ffuf',
          confidence: 'high',
        },
      ],
    };

    const result: NormalizeResult = normalize(db, artifactId, parseResult);

    // NormalizeResult の検証
    expect(result.hostsCreated).toBe(1);
    expect(result.servicesCreated).toBe(1);
    expect(result.httpEndpointsCreated).toBe(2);
    expect(result.inputsCreated).toBe(1);
    expect(result.endpointInputsCreated).toBe(1);
    expect(result.observationsCreated).toBe(2);
    expect(result.serviceObservationsCreated).toBe(0);
    expect(result.vulnerabilitiesCreated).toBe(0);
    expect(result.cvesCreated).toBe(0);

    // DB 状態の検証 — ホストとサービス
    const hosts = nodeRepo.findByKind('host');
    expect(hosts).toHaveLength(1);

    const hostServiceEdges = edgeRepo.findBySource(hosts[0].id, 'HOST_SERVICE');
    expect(hostServiceEdges).toHaveLength(1);
    const serviceId = hostServiceEdges[0].targetId;
    const serviceNode = nodeRepo.findById(serviceId)!;
    expect(parseProps<{ port: number }>(serviceNode.propsJson).port).toBe(80);

    // HTTP エンドポイント（SERVICE_ENDPOINT edge 経由）
    const epEdges = edgeRepo.findBySource(serviceId, 'SERVICE_ENDPOINT');
    expect(epEdges).toHaveLength(2);

    const epNodes = epEdges.map((e) => nodeRepo.findById(e.targetId)!);
    const paths = epNodes.map((n) => parseProps<{ path: string }>(n.propsJson).path).sort();
    expect(paths).toEqual(['/admin', '/login']);

    // 入力パラメータ（SERVICE_INPUT edge 経由）
    const inputEdges = edgeRepo.findBySource(serviceId, 'SERVICE_INPUT');
    expect(inputEdges).toHaveLength(1);

    const inputNode = nodeRepo.findById(inputEdges[0].targetId)!;
    const inputProps = parseProps<{ location: string; name: string }>(inputNode.propsJson);
    expect(inputProps.location).toBe('query');
    expect(inputProps.name).toBe('q');

    // エンドポイント ↔ 入力の紐づけ（ENDPOINT_INPUT edge）
    const adminEp = epNodes.find(
      (n) => parseProps<{ path: string }>(n.propsJson).path === '/admin',
    );
    expect(adminEp).toBeDefined();

    const epInputEdges = edgeRepo.findBySource(adminEp!.id, 'ENDPOINT_INPUT');
    expect(epInputEdges).toHaveLength(1);
    expect(epInputEdges[0].targetId).toBe(inputNode.id);

    // 観測値（INPUT_OBSERVATION edge 経由）
    const obsEdges = edgeRepo.findBySource(inputNode.id, 'INPUT_OBSERVATION');
    expect(obsEdges).toHaveLength(2);

    const obsNodes = obsEdges.map((e) => nodeRepo.findById(e.targetId)!);
    const rawValues = obsNodes
      .map((n) => parseProps<{ rawValue: string }>(n.propsJson).rawValue)
      .sort();
    expect(rawValues).toEqual(['admin', 'test']);
  });

  // -----------------------------------------------------------------------
  // 3. nuclei 結果を正規化する（vulnerabilities + cves）
  // -----------------------------------------------------------------------

  it('nuclei 結果を正規化する（vulnerabilities + cves）', () => {
    const parseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [{ authority: '10.0.0.1', authorityKind: 'IP' }],
      services: [
        {
          hostAuthority: '10.0.0.1',
          transport: 'tcp',
          port: 80,
          appProto: 'http',
          protoConfidence: 'high',
          state: 'open',
        },
      ],
      httpEndpoints: [
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          baseUri: 'http://10.0.0.1:80',
          method: 'GET',
          path: '/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd',
          statusCode: 200,
        },
      ],
      vulnerabilities: [
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          method: 'GET',
          path: '/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd',
          vulnType: 'lfi',
          title: 'Path Traversal',
          description: 'Apache 2.4.49 path traversal via cgi-bin',
          severity: 'critical',
          confidence: 'high',
        },
      ],
      cves: [
        {
          vulnerabilityTitle: 'Path Traversal',
          cveId: 'CVE-2021-41773',
          description: 'Apache HTTP Server 2.4.49 path traversal',
          cvssScore: 7.5,
        },
      ],
    };

    const result: NormalizeResult = normalize(db, artifactId, parseResult);

    // NormalizeResult の検証
    expect(result.hostsCreated).toBe(1);
    expect(result.servicesCreated).toBe(1);
    expect(result.httpEndpointsCreated).toBe(1);
    expect(result.vulnerabilitiesCreated).toBe(1);
    expect(result.cvesCreated).toBe(1);

    // DB 状態の検証 — vulnerability ノード
    const hosts = nodeRepo.findByKind('host');
    expect(hosts).toHaveLength(1);

    const hostServiceEdges = edgeRepo.findBySource(hosts[0].id, 'HOST_SERVICE');
    expect(hostServiceEdges).toHaveLength(1);
    const serviceId = hostServiceEdges[0].targetId;

    // SERVICE_VULNERABILITY edge 経由で vulnerability ノードを取得
    const vulnEdges = edgeRepo.findBySource(serviceId, 'SERVICE_VULNERABILITY');
    expect(vulnEdges).toHaveLength(1);

    const vulnNode = nodeRepo.findById(vulnEdges[0].targetId)!;
    const vulnProps = parseProps<{
      vulnType: string;
      title: string;
      severity: string;
      confidence: string;
    }>(vulnNode.propsJson);
    expect(vulnProps.vulnType).toBe('lfi');
    expect(vulnProps.title).toBe('Path Traversal');
    expect(vulnProps.severity).toBe('critical');
    expect(vulnProps.confidence).toBe('high');

    // ENDPOINT_VULNERABILITY edge も作成されていることを検証
    const epEdges = edgeRepo.findBySource(serviceId, 'SERVICE_ENDPOINT');
    expect(epEdges).toHaveLength(1);
    const endpointId = epEdges[0].targetId;

    const epVulnEdges = edgeRepo.findBySource(endpointId, 'ENDPOINT_VULNERABILITY');
    expect(epVulnEdges).toHaveLength(1);
    expect(epVulnEdges[0].targetId).toBe(vulnNode.id);

    // DB 状態の検証 — CVE ノード（VULNERABILITY_CVE edge 経由）
    const cveEdges = edgeRepo.findBySource(vulnNode.id, 'VULNERABILITY_CVE');
    expect(cveEdges).toHaveLength(1);

    const cveNode = nodeRepo.findById(cveEdges[0].targetId)!;
    const cveProps = parseProps<{
      cveId: string;
      cvssScore: number;
      description: string;
    }>(cveNode.propsJson);
    expect(cveProps.cveId).toBe('CVE-2021-41773');
    expect(cveProps.cvssScore).toBe(7.5);
    expect(cveProps.description).toBe('Apache HTTP Server 2.4.49 path traversal');
  });

  // -----------------------------------------------------------------------
  // 4. 既存ホストに対する重複登録はスキップする（upsert）
  // -----------------------------------------------------------------------

  it('既存ホストに対する重複登録はスキップする（upsert）', () => {
    // 1 回目: host 10.0.0.1 + service tcp/80
    const firstParseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [{ authority: '10.0.0.1', authorityKind: 'IP' }],
      services: [
        {
          hostAuthority: '10.0.0.1',
          transport: 'tcp',
          port: 80,
          appProto: 'http',
          protoConfidence: 'high',
          state: 'open',
        },
      ],
    };

    const result1 = normalize(db, artifactId, firstParseResult);
    expect(result1.hostsCreated).toBe(1);
    expect(result1.servicesCreated).toBe(1);

    // 2 回目の artifact を作成
    const artifact2Id = createArtifact(db, 'nmap', '/tmp/nmap-output-2.xml');

    // 2 回目: 同じ host 10.0.0.1 + 新しい service tcp/443
    const secondParseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [{ authority: '10.0.0.1', authorityKind: 'IP' }],
      services: [
        {
          hostAuthority: '10.0.0.1',
          transport: 'tcp',
          port: 443,
          appProto: 'https',
          protoConfidence: 'high',
          state: 'open',
        },
      ],
    };

    const result2 = normalize(db, artifact2Id, secondParseResult);
    expect(result2.hostsCreated).toBe(0);
    expect(result2.servicesCreated).toBe(1);

    // ホストは 1 件のまま
    const hosts = nodeRepo.findByKind('host');
    expect(hosts).toHaveLength(1);
    expect(parseProps<{ authority: string }>(hosts[0].propsJson).authority).toBe('10.0.0.1');

    // サービスは合計 2 件（HOST_SERVICE edge 経由）
    const hostServiceEdges = edgeRepo.findBySource(hosts[0].id, 'HOST_SERVICE');
    expect(hostServiceEdges).toHaveLength(2);

    const serviceNodes = hostServiceEdges.map((e) => nodeRepo.findById(e.targetId)!);
    const ports = serviceNodes
      .map((s) => parseProps<{ port: number }>(s.propsJson).port)
      .sort((a, b) => a - b);
    expect(ports).toEqual([80, 443]);
  });

  // -----------------------------------------------------------------------
  // 5. 既存サービスに対する重複登録はスキップする
  // -----------------------------------------------------------------------

  it('既存サービスに対する重複登録はスキップする', () => {
    // 1 回目: host 10.0.0.1 + service tcp/80
    const firstParseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [{ authority: '10.0.0.1', authorityKind: 'IP' }],
      services: [
        {
          hostAuthority: '10.0.0.1',
          transport: 'tcp',
          port: 80,
          appProto: 'http',
          protoConfidence: 'high',
          state: 'open',
        },
      ],
    };

    const result1 = normalize(db, artifactId, firstParseResult);
    expect(result1.hostsCreated).toBe(1);
    expect(result1.servicesCreated).toBe(1);

    // 2 回目の artifact を作成
    const artifact2Id = createArtifact(db, 'nmap', '/tmp/nmap-output-2.xml');

    // 2 回目: まったく同じ host + service
    const secondParseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [{ authority: '10.0.0.1', authorityKind: 'IP' }],
      services: [
        {
          hostAuthority: '10.0.0.1',
          transport: 'tcp',
          port: 80,
          appProto: 'http',
          protoConfidence: 'high',
          state: 'open',
        },
      ],
    };

    const result2 = normalize(db, artifact2Id, secondParseResult);
    expect(result2.hostsCreated).toBe(0);
    expect(result2.servicesCreated).toBe(0);

    // ホストは 1 件のまま
    const hosts = nodeRepo.findByKind('host');
    expect(hosts).toHaveLength(1);

    // サービスも 1 件のまま
    const hostServiceEdges = edgeRepo.findBySource(hosts[0].id, 'HOST_SERVICE');
    expect(hostServiceEdges).toHaveLength(1);

    const serviceNode = nodeRepo.findById(hostServiceEdges[0].targetId)!;
    expect(parseProps<{ port: number }>(serviceNode.propsJson).port).toBe(80);
  });

  // -----------------------------------------------------------------------
  // 6. 既存入力パラメータに対する重複登録はスキップする
  // -----------------------------------------------------------------------

  it('既存入力パラメータに対する重複登録はスキップする', () => {
    // 1 回目: host + service + input (query, 'q') + observation
    const firstParseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [{ authority: '10.0.0.1', authorityKind: 'IP' }],
      services: [
        {
          hostAuthority: '10.0.0.1',
          transport: 'tcp',
          port: 80,
          appProto: 'http',
          protoConfidence: 'high',
          state: 'open',
        },
      ],
      inputs: [
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          location: 'query',
          name: 'q',
        },
      ],
      observations: [
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          inputLocation: 'query',
          inputName: 'q',
          rawValue: 'admin',
          normValue: 'admin',
          source: 'ffuf',
          confidence: 'high',
        },
      ],
    };

    const result1 = normalize(db, artifactId, firstParseResult);
    expect(result1.inputsCreated).toBe(1);
    expect(result1.observationsCreated).toBe(1);

    // 2 回目の artifact を作成
    const artifact2Id = createArtifact(db, 'ffuf', '/tmp/ffuf-output-2.json');

    // 2 回目: 同じ input (query, 'q') + 新しい observation
    const secondParseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [{ authority: '10.0.0.1', authorityKind: 'IP' }],
      services: [
        {
          hostAuthority: '10.0.0.1',
          transport: 'tcp',
          port: 80,
          appProto: 'http',
          protoConfidence: 'high',
          state: 'open',
        },
      ],
      inputs: [
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          location: 'query',
          name: 'q',
        },
      ],
      observations: [
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          inputLocation: 'query',
          inputName: 'q',
          rawValue: 'search',
          normValue: 'search',
          source: 'ffuf',
          confidence: 'high',
        },
      ],
    };

    const result2 = normalize(db, artifact2Id, secondParseResult);
    expect(result2.inputsCreated).toBe(0);
    expect(result2.observationsCreated).toBe(1);

    // input は 1 件のまま（SERVICE_INPUT edge 経由）
    const hosts = nodeRepo.findByKind('host');
    const hostServiceEdges = edgeRepo.findBySource(hosts[0].id, 'HOST_SERVICE');
    const serviceId = hostServiceEdges[0].targetId;

    const inputEdges = edgeRepo.findBySource(serviceId, 'SERVICE_INPUT');
    expect(inputEdges).toHaveLength(1);

    const inputNode = nodeRepo.findById(inputEdges[0].targetId)!;
    expect(parseProps<{ name: string }>(inputNode.propsJson).name).toBe('q');

    // observation は合計 2 件（INPUT_OBSERVATION edge 経由）
    const obsEdges = edgeRepo.findBySource(inputNode.id, 'INPUT_OBSERVATION');
    expect(obsEdges).toHaveLength(2);

    const obsNodes = obsEdges.map((e) => nodeRepo.findById(e.targetId)!);
    const rawValues = obsNodes
      .map((n) => parseProps<{ rawValue: string }>(n.propsJson).rawValue)
      .sort();
    expect(rawValues).toEqual(['admin', 'search']);
  });

  // -----------------------------------------------------------------------
  // 7. 空の ParseResult を渡すとすべて 0 を返す
  // -----------------------------------------------------------------------

  it('空の ParseResult を渡すとすべて 0 を返す', () => {
    const result: NormalizeResult = normalize(db, artifactId, emptyParseResult());

    expect(result.hostsCreated).toBe(0);
    expect(result.servicesCreated).toBe(0);
    expect(result.serviceObservationsCreated).toBe(0);
    expect(result.httpEndpointsCreated).toBe(0);
    expect(result.inputsCreated).toBe(0);
    expect(result.endpointInputsCreated).toBe(0);
    expect(result.observationsCreated).toBe(0);
    expect(result.vulnerabilitiesCreated).toBe(0);
    expect(result.cvesCreated).toBe(0);

    // DB にも何も作成されていない
    expect(nodeRepo.findByKind('host')).toHaveLength(0);
  });

  // -----------------------------------------------------------------------
  // 8. トランザクション: normalize はアトミックに実行される
  // -----------------------------------------------------------------------

  it('トランザクション: normalize はアトミックに実行される', () => {
    // 正常な ParseResult で normalize を実行し、全データがコミットされることを検証
    const parseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [{ authority: '10.0.0.1', authorityKind: 'IP' }],
      services: [
        {
          hostAuthority: '10.0.0.1',
          transport: 'tcp',
          port: 80,
          appProto: 'http',
          protoConfidence: 'high',
          state: 'open',
        },
      ],
      httpEndpoints: [
        {
          hostAuthority: '10.0.0.1',
          port: 80,
          baseUri: 'http://10.0.0.1:80',
          method: 'GET',
          path: '/index',
          statusCode: 200,
        },
      ],
    };

    const result = normalize(db, artifactId, parseResult);

    // すべてが一括でコミットされている
    expect(result.hostsCreated).toBe(1);
    expect(result.servicesCreated).toBe(1);
    expect(result.httpEndpointsCreated).toBe(1);

    const hosts = nodeRepo.findByKind('host');
    expect(hosts).toHaveLength(1);

    const hostServiceEdges = edgeRepo.findBySource(hosts[0].id, 'HOST_SERVICE');
    expect(hostServiceEdges).toHaveLength(1);
    const serviceId = hostServiceEdges[0].targetId;

    const epEdges = edgeRepo.findBySource(serviceId, 'SERVICE_ENDPOINT');
    expect(epEdges).toHaveLength(1);

    const epNode = nodeRepo.findById(epEdges[0].targetId)!;
    expect(parseProps<{ path: string }>(epNode.propsJson).path).toBe('/index');
  });
});
