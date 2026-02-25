/**
 * sonobat — Normalizer
 *
 * ParseResult（パーサーの中間表現）を受け取り、
 * 自然キーで既存レコードを検索（upsert）しながら DB に書き込む。
 * 全操作はトランザクションでラップし、アトミックに実行する。
 */

import type Database from 'better-sqlite3';
import type { ParseResult } from '../types/parser.js';
import { HostRepository } from '../db/repository/host-repository.js';
import { ServiceRepository } from '../db/repository/service-repository.js';
import { ServiceObservationRepository } from '../db/repository/service-observation-repository.js';
import { HttpEndpointRepository } from '../db/repository/http-endpoint-repository.js';
import { InputRepository } from '../db/repository/input-repository.js';
import { EndpointInputRepository } from '../db/repository/endpoint-input-repository.js';
import { ObservationRepository } from '../db/repository/observation-repository.js';
import { VulnerabilityRepository } from '../db/repository/vulnerability-repository.js';
import { CveRepository } from '../db/repository/cve-repository.js';

// ============================================================
// 結果型
// ============================================================

/** normalize() の実行結果。各エンティティの新規作成数を返す。 */
export interface NormalizeResult {
  hostsCreated: number;
  servicesCreated: number;
  serviceObservationsCreated: number;
  httpEndpointsCreated: number;
  inputsCreated: number;
  endpointInputsCreated: number;
  observationsCreated: number;
  vulnerabilitiesCreated: number;
  cvesCreated: number;
}

// ============================================================
// normalize
// ============================================================

/**
 * ParseResult を DB に正規化して書き込む。
 *
 * - 自然キー（authority, host_id+transport+port 等）で既存レコードを検索し、
 *   存在すれば再利用、なければ新規作成する（upsert パターン）。
 * - 全操作は 1 トランザクション内で実行される。
 *
 * @param db         better-sqlite3 の Database インスタンス
 * @param artifactId 根拠となる Artifact の ID（evidence_artifact_id に設定）
 * @param parseResult パーサーが返した中間表現
 * @returns 各エンティティの新規作成数
 */
export function normalize(
  db: Database.Database,
  artifactId: string,
  parseResult: ParseResult,
): NormalizeResult {
  const hostRepo = new HostRepository(db);
  const serviceRepo = new ServiceRepository(db);
  const serviceObsRepo = new ServiceObservationRepository(db);
  const httpEndpointRepo = new HttpEndpointRepository(db);
  const inputRepo = new InputRepository(db);
  const endpointInputRepo = new EndpointInputRepository(db);
  const observationRepo = new ObservationRepository(db);
  const vulnRepo = new VulnerabilityRepository(db);
  const cveRepo = new CveRepository(db);

  const run = db.transaction((): NormalizeResult => {
    const result: NormalizeResult = {
      hostsCreated: 0,
      servicesCreated: 0,
      serviceObservationsCreated: 0,
      httpEndpointsCreated: 0,
      inputsCreated: 0,
      endpointInputsCreated: 0,
      observationsCreated: 0,
      vulnerabilitiesCreated: 0,
      cvesCreated: 0,
    };

    // ---------------------------------------------------------
    // 自然キー → DB ID のマッピング
    // ---------------------------------------------------------
    const hostIdByAuthority = new Map<string, string>();
    // key: "hostId:transport:port"
    const serviceIdByKey = new Map<string, string>();
    // key: "serviceId:method:path"
    const endpointIdByKey = new Map<string, string>();
    // key: "serviceId:location:name"
    const inputIdByKey = new Map<string, string>();
    // key: vulnerability title → DB ID
    const vulnIdByTitle = new Map<string, string>();

    // ---------------------------------------------------------
    // 1. Upsert hosts
    // ---------------------------------------------------------
    for (const parsed of parseResult.hosts) {
      const existing = hostRepo.findByAuthority(parsed.authority);
      if (existing) {
        hostIdByAuthority.set(parsed.authority, existing.id);
      } else {
        const host = hostRepo.create({
          authorityKind: parsed.authorityKind,
          authority: parsed.authority,
          resolvedIpsJson: JSON.stringify(parsed.resolvedIps ?? []),
        });
        hostIdByAuthority.set(parsed.authority, host.id);
        result.hostsCreated++;
      }
    }

    // ---------------------------------------------------------
    // 2. Upsert services
    // ---------------------------------------------------------
    for (const parsed of parseResult.services) {
      const hostId = hostIdByAuthority.get(parsed.hostAuthority);
      if (!hostId) continue;

      const svcKey = `${hostId}:${parsed.transport}:${parsed.port}`;
      if (serviceIdByKey.has(svcKey)) continue;

      // DB から既存サービスを検索
      const existingServices = serviceRepo.findByHostId(hostId);
      const existing = existingServices.find(
        (s) => s.transport === parsed.transport && s.port === parsed.port,
      );

      if (existing) {
        serviceIdByKey.set(svcKey, existing.id);
      } else {
        const service = serviceRepo.create({
          hostId,
          transport: parsed.transport,
          port: parsed.port,
          appProto: parsed.appProto,
          protoConfidence: parsed.protoConfidence,
          banner: parsed.banner,
          product: parsed.product,
          version: parsed.version,
          state: parsed.state,
          evidenceArtifactId: artifactId,
        });
        serviceIdByKey.set(svcKey, service.id);
        result.servicesCreated++;
      }
    }

    // ---------------------------------------------------------
    // ヘルパー: hostAuthority + port → serviceId を解決
    // HTTP 系エンティティは transport が常に tcp
    // ---------------------------------------------------------
    function resolveServiceId(hostAuthority: string, port: number): string | undefined {
      const hostId = hostIdByAuthority.get(hostAuthority);
      if (!hostId) return undefined;
      return serviceIdByKey.get(`${hostId}:tcp:${port}`);
    }

    // ---------------------------------------------------------
    // 3. Service observations
    // ---------------------------------------------------------
    for (const parsed of parseResult.serviceObservations) {
      const hostId = hostIdByAuthority.get(parsed.hostAuthority);
      if (!hostId) continue;

      const svcKey = `${hostId}:${parsed.transport}:${parsed.port}`;
      const serviceId = serviceIdByKey.get(svcKey);
      if (!serviceId) continue;

      serviceObsRepo.create({
        serviceId,
        key: parsed.key,
        value: parsed.value,
        confidence: parsed.confidence,
        evidenceArtifactId: artifactId,
      });
      result.serviceObservationsCreated++;
    }

    // ---------------------------------------------------------
    // 4. Upsert HTTP endpoints
    // ---------------------------------------------------------
    for (const parsed of parseResult.httpEndpoints) {
      const serviceId = resolveServiceId(parsed.hostAuthority, parsed.port);
      if (!serviceId) continue;

      const epKey = `${serviceId}:${parsed.method}:${parsed.path}`;
      if (endpointIdByKey.has(epKey)) continue;

      const existingEndpoints = httpEndpointRepo.findByServiceId(serviceId);
      const existing = existingEndpoints.find(
        (e) => e.method === parsed.method && e.path === parsed.path,
      );

      if (existing) {
        endpointIdByKey.set(epKey, existing.id);
      } else {
        const endpoint = httpEndpointRepo.create({
          serviceId,
          baseUri: parsed.baseUri,
          method: parsed.method,
          path: parsed.path,
          statusCode: parsed.statusCode,
          contentLength: parsed.contentLength,
          words: parsed.words,
          lines: parsed.lines,
          evidenceArtifactId: artifactId,
        });
        endpointIdByKey.set(epKey, endpoint.id);
        result.httpEndpointsCreated++;
      }
    }

    // ---------------------------------------------------------
    // 5. Upsert inputs
    // ---------------------------------------------------------
    for (const parsed of parseResult.inputs) {
      const serviceId = resolveServiceId(parsed.hostAuthority, parsed.port);
      if (!serviceId) continue;

      const inKey = `${serviceId}:${parsed.location}:${parsed.name}`;
      if (inputIdByKey.has(inKey)) continue;

      const existingInputs = inputRepo.findByServiceId(serviceId);
      const existing = existingInputs.find(
        (i) => i.location === parsed.location && i.name === parsed.name,
      );

      if (existing) {
        inputIdByKey.set(inKey, existing.id);
      } else {
        const input = inputRepo.create({
          serviceId,
          location: parsed.location,
          name: parsed.name,
          typeHint: parsed.typeHint,
        });
        inputIdByKey.set(inKey, input.id);
        result.inputsCreated++;
      }
    }

    // ---------------------------------------------------------
    // 6. Upsert endpoint_inputs
    // ---------------------------------------------------------
    for (const parsed of parseResult.endpointInputs) {
      const serviceId = resolveServiceId(parsed.hostAuthority, parsed.port);
      if (!serviceId) continue;

      const epKey = `${serviceId}:${parsed.method}:${parsed.path}`;
      const endpointId = endpointIdByKey.get(epKey);
      if (!endpointId) continue;

      const inKey = `${serviceId}:${parsed.inputLocation}:${parsed.inputName}`;
      const inputId = inputIdByKey.get(inKey);
      if (!inputId) continue;

      // 既存リンクの確認
      const existingLinks = endpointInputRepo.findByEndpointId(endpointId);
      const alreadyLinked = existingLinks.some((l) => l.inputId === inputId);
      if (alreadyLinked) continue;

      endpointInputRepo.create({
        endpointId,
        inputId,
        evidenceArtifactId: artifactId,
      });
      result.endpointInputsCreated++;
    }

    // ---------------------------------------------------------
    // 7. Observations（常に新規作成）
    // ---------------------------------------------------------
    for (const parsed of parseResult.observations) {
      const serviceId = resolveServiceId(parsed.hostAuthority, parsed.port);
      if (!serviceId) continue;

      const inKey = `${serviceId}:${parsed.inputLocation}:${parsed.inputName}`;
      const inputId = inputIdByKey.get(inKey);
      if (!inputId) continue;

      observationRepo.create({
        inputId,
        rawValue: parsed.rawValue,
        normValue: parsed.normValue,
        source: parsed.source,
        confidence: parsed.confidence,
        evidenceArtifactId: artifactId,
        observedAt: new Date().toISOString(),
      });
      result.observationsCreated++;
    }

    // ---------------------------------------------------------
    // 8. Vulnerabilities
    // ---------------------------------------------------------
    for (const parsed of parseResult.vulnerabilities) {
      const serviceId = resolveServiceId(parsed.hostAuthority, parsed.port);
      if (!serviceId) continue;

      // endpoint への紐づけ（任意）
      let endpointId: string | undefined;
      if (parsed.method && parsed.path) {
        const epKey = `${serviceId}:${parsed.method}:${parsed.path}`;
        endpointId = endpointIdByKey.get(epKey);
      }

      const vuln = vulnRepo.create({
        serviceId,
        endpointId,
        vulnType: parsed.vulnType,
        title: parsed.title,
        description: parsed.description,
        severity: parsed.severity,
        confidence: parsed.confidence,
        evidenceArtifactId: artifactId,
      });
      vulnIdByTitle.set(parsed.title, vuln.id);
      result.vulnerabilitiesCreated++;
    }

    // ---------------------------------------------------------
    // 9. CVEs
    // ---------------------------------------------------------
    for (const parsed of parseResult.cves) {
      const vulnId = vulnIdByTitle.get(parsed.vulnerabilityTitle);
      if (!vulnId) continue;

      cveRepo.create({
        vulnerabilityId: vulnId,
        cveId: parsed.cveId,
        description: parsed.description,
        cvssScore: parsed.cvssScore,
        cvssVector: parsed.cvssVector,
        referenceUrl: parsed.referenceUrl,
      });
      result.cvesCreated++;
    }

    return result;
  });

  return run();
}
