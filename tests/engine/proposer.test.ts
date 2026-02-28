import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../src/db/migrate.js';
import { propose } from '../../src/engine/proposer.js';
import { HostRepository } from '../../src/db/repository/host-repository.js';
import { ArtifactRepository } from '../../src/db/repository/artifact-repository.js';
import { ServiceRepository } from '../../src/db/repository/service-repository.js';
import { HttpEndpointRepository } from '../../src/db/repository/http-endpoint-repository.js';
import { InputRepository } from '../../src/db/repository/input-repository.js';
import { EndpointInputRepository } from '../../src/db/repository/endpoint-input-repository.js';
import { ObservationRepository } from '../../src/db/repository/observation-repository.js';
import { VhostRepository } from '../../src/db/repository/vhost-repository.js';
import { VulnerabilityRepository } from '../../src/db/repository/vulnerability-repository.js';

function now(): string {
  return new Date().toISOString();
}

describe('Proposer', () => {
  let db: InstanceType<typeof Database>;
  let hostRepo: HostRepository;
  let artifactRepo: ArtifactRepository;
  let serviceRepo: ServiceRepository;
  let httpEndpointRepo: HttpEndpointRepository;
  let inputRepo: InputRepository;
  let endpointInputRepo: EndpointInputRepository;
  let observationRepo: ObservationRepository;
  let vhostRepo: VhostRepository;
  let vulnRepo: VulnerabilityRepository;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    hostRepo = new HostRepository(db);
    artifactRepo = new ArtifactRepository(db);
    serviceRepo = new ServiceRepository(db);
    httpEndpointRepo = new HttpEndpointRepository(db);
    inputRepo = new InputRepository(db);
    endpointInputRepo = new EndpointInputRepository(db);
    observationRepo = new ObservationRepository(db);
    vhostRepo = new VhostRepository(db);
    vulnRepo = new VulnerabilityRepository(db);
  });

  it('propose — ホストにサービスがない場合 nmap_scan を提案', () => {
    hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });

    const actions = propose(db);

    expect(actions.length).toBeGreaterThanOrEqual(1);
    expect(actions.some((a) => a.kind === 'nmap_scan')).toBe(true);
    const nmapAction = actions.find((a) => a.kind === 'nmap_scan');
    expect(nmapAction?.command).toContain('10.0.0.1');
  });

  it('propose — HTTP サービスにエンドポイントがない場合 ffuf_discovery を提案', () => {
    const host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/scan.xml',
      capturedAt: now(),
    });
    serviceRepo.create({
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    });

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'ffuf_discovery')).toBe(true);
  });

  it('propose — エンドポイントに input がない場合 parameter_discovery を提案', () => {
    const host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/scan.xml',
      capturedAt: now(),
    });
    const service = serviceRepo.create({
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    });
    httpEndpointRepo.create({
      serviceId: service.id,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/index',
      evidenceArtifactId: artifact.id,
    });

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'parameter_discovery')).toBe(true);
  });

  it('propose — input に observation がない場合 value_collection を提案', () => {
    const host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/scan.xml',
      capturedAt: now(),
    });
    const service = serviceRepo.create({
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    });
    const endpoint = httpEndpointRepo.create({
      serviceId: service.id,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/index',
      evidenceArtifactId: artifact.id,
    });
    const input = inputRepo.create({
      serviceId: service.id,
      location: 'query',
      name: 'id',
    });
    endpointInputRepo.create({
      endpointId: endpoint.id,
      inputId: input.id,
      evidenceArtifactId: artifact.id,
    });

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'value_collection')).toBe(true);
  });

  it('propose — HTTP サービスに vhost がない場合 vhost_discovery を提案', () => {
    const host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/scan.xml',
      capturedAt: now(),
    });
    serviceRepo.create({
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    });

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'vhost_discovery')).toBe(true);
  });

  it('propose — HTTP サービスに脆弱性がない場合 nuclei_scan を提案', () => {
    const host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/scan.xml',
      capturedAt: now(),
    });
    serviceRepo.create({
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    });

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'nuclei_scan')).toBe(true);
  });

  it('propose — 全て揃っている場合は空配列を返す', () => {
    const host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/scan.xml',
      capturedAt: now(),
    });
    const service = serviceRepo.create({
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    });
    const endpoint = httpEndpointRepo.create({
      serviceId: service.id,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/index',
      evidenceArtifactId: artifact.id,
    });
    const input = inputRepo.create({
      serviceId: service.id,
      location: 'query',
      name: 'id',
    });
    endpointInputRepo.create({
      endpointId: endpoint.id,
      inputId: input.id,
      evidenceArtifactId: artifact.id,
    });
    observationRepo.create({
      inputId: input.id,
      rawValue: '1',
      normValue: '1',
      source: 'ffuf_url',
      confidence: 'high',
      evidenceArtifactId: artifact.id,
      observedAt: now(),
    });
    vhostRepo.create({
      hostId: host.id,
      hostname: 'www.example.com',
      source: 'cert',
      evidenceArtifactId: artifact.id,
    });
    vulnRepo.create({
      serviceId: service.id,
      vulnType: 'sqli',
      title: 'SQL Injection',
      severity: 'critical',
      confidence: 'high',
      evidenceArtifactId: artifact.id,
    });

    const actions = propose(db);

    expect(actions).toHaveLength(0);
  });

  it('propose — hostId 指定時は該当ホストのみ対象', () => {
    // host1: サービスなし
    const host1 = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    // host2: 全データ揃い
    const host2 = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.2',
      resolvedIpsJson: '[]',
    });
    const artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/scan.xml',
      capturedAt: now(),
    });
    const service2 = serviceRepo.create({
      hostId: host2.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    });
    const endpoint2 = httpEndpointRepo.create({
      serviceId: service2.id,
      baseUri: 'http://10.0.0.2:80',
      method: 'GET',
      path: '/index',
      evidenceArtifactId: artifact.id,
    });
    const input = inputRepo.create({
      serviceId: service2.id,
      location: 'query',
      name: 'id',
    });
    endpointInputRepo.create({
      endpointId: endpoint2.id,
      inputId: input.id,
      evidenceArtifactId: artifact.id,
    });
    observationRepo.create({
      inputId: input.id,
      rawValue: '1',
      normValue: '1',
      source: 'ffuf_url',
      confidence: 'high',
      evidenceArtifactId: artifact.id,
      observedAt: now(),
    });
    vhostRepo.create({
      hostId: host2.id,
      hostname: 'www.example.com',
      source: 'cert',
      evidenceArtifactId: artifact.id,
    });
    vulnRepo.create({
      serviceId: service2.id,
      vulnType: 'sqli',
      title: 'SQL Injection',
      severity: 'critical',
      confidence: 'high',
      evidenceArtifactId: artifact.id,
    });

    // host2 は全て揃っている → 空
    const actionsHost2 = propose(db, host2.id);
    expect(actionsHost2).toHaveLength(0);

    // host1 はサービスなし → nmap_scan
    const actionsHost1 = propose(db, host1.id);
    expect(actionsHost1.length).toBeGreaterThanOrEqual(1);
    expect(actionsHost1.some((a) => a.kind === 'nmap_scan')).toBe(true);
  });

  // =========================================================
  // 新規テスト: エンドポイント単位の parameter_discovery
  // =========================================================

  it('propose — エンドポイント A に input あり、B に input なし → B のみ parameter_discovery 提案', () => {
    const host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/scan.xml',
      capturedAt: now(),
    });
    const service = serviceRepo.create({
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    });

    // エンドポイント A: input あり
    const endpointA = httpEndpointRepo.create({
      serviceId: service.id,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/login',
      evidenceArtifactId: artifact.id,
    });
    const input = inputRepo.create({
      serviceId: service.id,
      location: 'query',
      name: 'user',
    });
    endpointInputRepo.create({
      endpointId: endpointA.id,
      inputId: input.id,
      evidenceArtifactId: artifact.id,
    });

    // エンドポイント B: input なし
    httpEndpointRepo.create({
      serviceId: service.id,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/admin',
      evidenceArtifactId: artifact.id,
    });

    // vhost + vuln を追加してノイズを減らす
    vhostRepo.create({
      hostId: host.id,
      hostname: 'www.example.com',
      source: 'cert',
      evidenceArtifactId: artifact.id,
    });
    vulnRepo.create({
      serviceId: service.id,
      vulnType: 'sqli',
      title: 'SQL Injection',
      severity: 'critical',
      confidence: 'high',
      evidenceArtifactId: artifact.id,
    });

    const actions = propose(db);

    // B のみ parameter_discovery が提案される
    const paramDiscovery = actions.filter((a) => a.kind === 'parameter_discovery');
    expect(paramDiscovery).toHaveLength(1);
    expect(paramDiscovery[0].description).toContain('/admin');
  });

  // =========================================================
  // 新規テスト: value_fuzz
  // =========================================================

  it('propose — input + observation あり、vulnerability なし → value_fuzz を提案', () => {
    const host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/scan.xml',
      capturedAt: now(),
    });
    const service = serviceRepo.create({
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    });
    const endpoint = httpEndpointRepo.create({
      serviceId: service.id,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/search',
      evidenceArtifactId: artifact.id,
    });
    const input = inputRepo.create({
      serviceId: service.id,
      location: 'query',
      name: 'q',
    });
    endpointInputRepo.create({
      endpointId: endpoint.id,
      inputId: input.id,
      evidenceArtifactId: artifact.id,
    });
    observationRepo.create({
      inputId: input.id,
      rawValue: 'test',
      normValue: 'test',
      source: 'ffuf_url',
      confidence: 'high',
      evidenceArtifactId: artifact.id,
      observedAt: now(),
    });
    // vhost を追加してノイズを減らす
    vhostRepo.create({
      hostId: host.id,
      hostname: 'www.example.com',
      source: 'cert',
      evidenceArtifactId: artifact.id,
    });
    // 脆弱性なし → value_fuzz が提案されるべき

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'value_fuzz')).toBe(true);
    const fuzzAction = actions.find((a) => a.kind === 'value_fuzz');
    expect(fuzzAction?.description).toContain('q');
    expect(fuzzAction?.params).toHaveProperty('inputId', input.id);
  });

  it('propose — input + observation + vulnerability あり → value_fuzz を提案しない', () => {
    const host = hostRepo.create({
      authorityKind: 'IP',
      authority: '10.0.0.1',
      resolvedIpsJson: '[]',
    });
    const artifact = artifactRepo.create({
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/scan.xml',
      capturedAt: now(),
    });
    const service = serviceRepo.create({
      hostId: host.id,
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
      evidenceArtifactId: artifact.id,
    });
    const endpoint = httpEndpointRepo.create({
      serviceId: service.id,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/search',
      evidenceArtifactId: artifact.id,
    });
    const input = inputRepo.create({
      serviceId: service.id,
      location: 'query',
      name: 'q',
    });
    endpointInputRepo.create({
      endpointId: endpoint.id,
      inputId: input.id,
      evidenceArtifactId: artifact.id,
    });
    observationRepo.create({
      inputId: input.id,
      rawValue: 'test',
      normValue: 'test',
      source: 'ffuf_url',
      confidence: 'high',
      evidenceArtifactId: artifact.id,
      observedAt: now(),
    });
    vhostRepo.create({
      hostId: host.id,
      hostname: 'www.example.com',
      source: 'cert',
      evidenceArtifactId: artifact.id,
    });
    // 脆弱性あり → value_fuzz は提案されない
    vulnRepo.create({
      serviceId: service.id,
      vulnType: 'sqli',
      title: 'SQL Injection',
      severity: 'critical',
      confidence: 'high',
      evidenceArtifactId: artifact.id,
    });

    const actions = propose(db);

    expect(actions.some((a) => a.kind === 'value_fuzz')).toBe(false);
  });
});
