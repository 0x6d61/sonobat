import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../src/db/migrate.js';
import { ArtifactRepository } from '../../src/db/repository/artifact-repository.js';
import { HostRepository } from '../../src/db/repository/host-repository.js';
import { ServiceRepository } from '../../src/db/repository/service-repository.js';
import { ServiceObservationRepository } from '../../src/db/repository/service-observation-repository.js';
import { HttpEndpointRepository } from '../../src/db/repository/http-endpoint-repository.js';
import { InputRepository } from '../../src/db/repository/input-repository.js';
import { EndpointInputRepository } from '../../src/db/repository/endpoint-input-repository.js';
import { ObservationRepository } from '../../src/db/repository/observation-repository.js';
import { VulnerabilityRepository } from '../../src/db/repository/vulnerability-repository.js';
import { CveRepository } from '../../src/db/repository/cve-repository.js';
import { normalize } from '../../src/engine/normalizer.js';
import type { NormalizeResult } from '../../src/engine/normalizer.js';
import { emptyParseResult } from '../../src/types/parser.js';
import type { ParseResult } from '../../src/types/parser.js';
import type { Artifact } from '../../src/types/entities.js';

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('normalize', () => {
  let db: InstanceType<typeof Database>;
  let artifactRepo: ArtifactRepository;
  let hostRepo: HostRepository;
  let serviceRepo: ServiceRepository;
  let serviceObsRepo: ServiceObservationRepository;
  let httpEndpointRepo: HttpEndpointRepository;
  let inputRepo: InputRepository;
  let endpointInputRepo: EndpointInputRepository;
  let observationRepo: ObservationRepository;
  let vulnRepo: VulnerabilityRepository;
  let cveRepo: CveRepository;

  let artifact: Artifact;
  let artifactId: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);

    artifactRepo = new ArtifactRepository(db);
    hostRepo = new HostRepository(db);
    serviceRepo = new ServiceRepository(db);
    serviceObsRepo = new ServiceObservationRepository(db);
    httpEndpointRepo = new HttpEndpointRepository(db);
    inputRepo = new InputRepository(db);
    endpointInputRepo = new EndpointInputRepository(db);
    observationRepo = new ObservationRepository(db);
    vulnRepo = new VulnerabilityRepository(db);
    cveRepo = new CveRepository(db);

    // FK 制約を満たすためにアーティファクトレコードを事前作成
    artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/scan-output.xml',
      capturedAt: new Date().toISOString(),
    });
    artifactId = artifact.id;
  });

  // -----------------------------------------------------------------------
  // 1. nmap 結果を正規化する（hosts + services + serviceObservations）
  // -----------------------------------------------------------------------

  it('nmap 結果を正規化する（hosts + services + serviceObservations）', () => {
    const parseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [
        { authority: '10.0.0.1', authorityKind: 'IP' },
      ],
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

    // DB 状態の検証
    const hosts = hostRepo.findAll();
    expect(hosts).toHaveLength(1);
    expect(hosts[0].authority).toBe('10.0.0.1');
    expect(hosts[0].authorityKind).toBe('IP');

    const services = serviceRepo.findByHostId(hosts[0].id);
    expect(services).toHaveLength(2);

    const ports = services.map((s) => s.port).sort((a, b) => a - b);
    expect(ports).toEqual([22, 80]);

    // ssh サービスに紐づく serviceObservation を検証
    const sshService = services.find((s) => s.port === 22);
    expect(sshService).toBeDefined();

    const observations = serviceObsRepo.findByServiceId(sshService!.id);
    expect(observations).toHaveLength(1);
    expect(observations[0].key).toBe('os');
    expect(observations[0].value).toBe('Linux 5.4');
  });

  // -----------------------------------------------------------------------
  // 2. ffuf 結果を正規化する（endpoints + inputs + observations + endpointInputs）
  // -----------------------------------------------------------------------

  it('ffuf 結果を正規化する（endpoints + inputs + observations + endpointInputs）', () => {
    const parseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [
        { authority: '10.0.0.1', authorityKind: 'IP' },
      ],
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
    const hosts = hostRepo.findAll();
    expect(hosts).toHaveLength(1);

    const services = serviceRepo.findByHostId(hosts[0].id);
    expect(services).toHaveLength(1);
    expect(services[0].port).toBe(80);

    // HTTP エンドポイント
    const endpoints = httpEndpointRepo.findByServiceId(services[0].id);
    expect(endpoints).toHaveLength(2);

    const paths = endpoints.map((e) => e.path).sort();
    expect(paths).toEqual(['/admin', '/login']);

    // 入力パラメータ
    const inputs = inputRepo.findByServiceId(services[0].id);
    expect(inputs).toHaveLength(1);
    expect(inputs[0].location).toBe('query');
    expect(inputs[0].name).toBe('q');

    // エンドポイント ↔ 入力の紐づけ
    const adminEndpoint = endpoints.find((e) => e.path === '/admin');
    expect(adminEndpoint).toBeDefined();

    const epInputs = endpointInputRepo.findByEndpointId(adminEndpoint!.id);
    expect(epInputs).toHaveLength(1);
    expect(epInputs[0].inputId).toBe(inputs[0].id);

    // 観測値
    const obs = observationRepo.findByInputId(inputs[0].id);
    expect(obs).toHaveLength(2);

    const rawValues = obs.map((o) => o.rawValue).sort();
    expect(rawValues).toEqual(['admin', 'test']);
  });

  // -----------------------------------------------------------------------
  // 3. nuclei 結果を正規化する（vulnerabilities + cves）
  // -----------------------------------------------------------------------

  it('nuclei 結果を正規化する（vulnerabilities + cves）', () => {
    const parseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [
        { authority: '10.0.0.1', authorityKind: 'IP' },
      ],
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

    // DB 状態の検証 — 脆弱性
    const hosts = hostRepo.findAll();
    expect(hosts).toHaveLength(1);

    const services = serviceRepo.findByHostId(hosts[0].id);
    expect(services).toHaveLength(1);

    const vulns = vulnRepo.findByServiceId(services[0].id);
    expect(vulns).toHaveLength(1);
    expect(vulns[0].vulnType).toBe('lfi');
    expect(vulns[0].title).toBe('Path Traversal');
    expect(vulns[0].severity).toBe('critical');
    expect(vulns[0].confidence).toBe('high');

    // DB 状態の検証 — CVE
    const cves = cveRepo.findByVulnerabilityId(vulns[0].id);
    expect(cves).toHaveLength(1);
    expect(cves[0].cveId).toBe('CVE-2021-41773');
    expect(cves[0].cvssScore).toBe(7.5);
    expect(cves[0].description).toBe('Apache HTTP Server 2.4.49 path traversal');
  });

  // -----------------------------------------------------------------------
  // 4. 既存ホストに対する重複登録はスキップする（upsert）
  // -----------------------------------------------------------------------

  it('既存ホストに対する重複登録はスキップする（upsert）', () => {
    // 1 回目: host 10.0.0.1 + service tcp/80
    const firstParseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [
        { authority: '10.0.0.1', authorityKind: 'IP' },
      ],
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
    const artifact2 = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/nmap-output-2.xml',
      capturedAt: new Date().toISOString(),
    });

    // 2 回目: 同じ host 10.0.0.1 + 新しい service tcp/443
    const secondParseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [
        { authority: '10.0.0.1', authorityKind: 'IP' },
      ],
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

    const result2 = normalize(db, artifact2.id, secondParseResult);
    expect(result2.hostsCreated).toBe(0);
    expect(result2.servicesCreated).toBe(1);

    // ホストは 1 件のまま
    const hosts = hostRepo.findAll();
    expect(hosts).toHaveLength(1);
    expect(hosts[0].authority).toBe('10.0.0.1');

    // サービスは合計 2 件
    const services = serviceRepo.findByHostId(hosts[0].id);
    expect(services).toHaveLength(2);

    const ports = services.map((s) => s.port).sort((a, b) => a - b);
    expect(ports).toEqual([80, 443]);
  });

  // -----------------------------------------------------------------------
  // 5. 既存サービスに対する重複登録はスキップする
  // -----------------------------------------------------------------------

  it('既存サービスに対する重複登録はスキップする', () => {
    // 1 回目: host 10.0.0.1 + service tcp/80
    const firstParseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [
        { authority: '10.0.0.1', authorityKind: 'IP' },
      ],
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
    const artifact2 = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/nmap-output-2.xml',
      capturedAt: new Date().toISOString(),
    });

    // 2 回目: まったく同じ host + service
    const secondParseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [
        { authority: '10.0.0.1', authorityKind: 'IP' },
      ],
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

    const result2 = normalize(db, artifact2.id, secondParseResult);
    expect(result2.hostsCreated).toBe(0);
    expect(result2.servicesCreated).toBe(0);

    // ホストは 1 件のまま
    const hosts = hostRepo.findAll();
    expect(hosts).toHaveLength(1);

    // サービスも 1 件のまま
    const services = serviceRepo.findByHostId(hosts[0].id);
    expect(services).toHaveLength(1);
    expect(services[0].port).toBe(80);
  });

  // -----------------------------------------------------------------------
  // 6. 既存入力パラメータに対する重複登録はスキップする
  // -----------------------------------------------------------------------

  it('既存入力パラメータに対する重複登録はスキップする', () => {
    // 1 回目: host + service + input (query, 'q') + observation
    const firstParseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [
        { authority: '10.0.0.1', authorityKind: 'IP' },
      ],
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
    const artifact2 = artifactRepo.create({
      tool: 'ffuf',
      kind: 'tool_output',
      path: '/tmp/ffuf-output-2.json',
      capturedAt: new Date().toISOString(),
    });

    // 2 回目: 同じ input (query, 'q') + 新しい observation
    const secondParseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [
        { authority: '10.0.0.1', authorityKind: 'IP' },
      ],
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

    const result2 = normalize(db, artifact2.id, secondParseResult);
    expect(result2.inputsCreated).toBe(0);
    expect(result2.observationsCreated).toBe(1);

    // input は 1 件のまま
    const hosts = hostRepo.findAll();
    const services = serviceRepo.findByHostId(hosts[0].id);
    const inputs = inputRepo.findByServiceId(services[0].id);
    expect(inputs).toHaveLength(1);
    expect(inputs[0].name).toBe('q');

    // observation は合計 2 件
    const obs = observationRepo.findByInputId(inputs[0].id);
    expect(obs).toHaveLength(2);

    const rawValues = obs.map((o) => o.rawValue).sort();
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
    expect(hostRepo.findAll()).toHaveLength(0);
  });

  // -----------------------------------------------------------------------
  // 8. トランザクション: normalize はアトミックに実行される
  // -----------------------------------------------------------------------

  it('トランザクション: normalize はアトミックに実行される', () => {
    // 正常な ParseResult で normalize を実行し、全データがコミットされることを検証
    const parseResult: ParseResult = {
      ...emptyParseResult(),
      hosts: [
        { authority: '10.0.0.1', authorityKind: 'IP' },
      ],
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

    const hosts = hostRepo.findAll();
    expect(hosts).toHaveLength(1);

    const services = serviceRepo.findByHostId(hosts[0].id);
    expect(services).toHaveLength(1);

    const endpoints = httpEndpointRepo.findByServiceId(services[0].id);
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0].path).toBe('/index');
  });
});
