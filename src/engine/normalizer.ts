/**
 * sonobat — Normalizer (Graph-native)
 *
 * ParseResult（パーサーの中間表現）を受け取り、
 * NodeRepository / EdgeRepository を使ってグラフ DB に書き込む。
 * 全操作はトランザクションでラップし、アトミックに実行する。
 */

import type Database from 'better-sqlite3';
import type { ParseResult } from '../types/parser.js';
import { NodeRepository } from '../db/repository/node-repository.js';
import { EdgeRepository } from '../db/repository/edge-repository.js';

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
 * ParseResult を DB に正規化して書き込む（Graph-native 版）。
 *
 * - NodeRepository.upsert() で自然キーによる重複排除を行い、
 *   EdgeRepository.upsert() でリレーションを作成する。
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
  const nodeRepo = new NodeRepository(db);
  const edgeRepo = new EdgeRepository(db);

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
    // 自然キー → ノード ID のマッピング
    // ---------------------------------------------------------
    const hostIdByAuthority = new Map<string, string>();
    // key: "hostNodeId:transport:port"
    const serviceIdByKey = new Map<string, string>();
    // key: "serviceNodeId:method:path"
    const endpointIdByKey = new Map<string, string>();
    // key: "serviceNodeId:location:name"
    const inputIdByKey = new Map<string, string>();
    // key: vulnerability title → node ID
    const vulnIdByTitle = new Map<string, string>();

    // ---------------------------------------------------------
    // 1. Upsert hosts
    // ---------------------------------------------------------
    for (const parsed of parseResult.hosts) {
      const { node, created } = nodeRepo.upsert('host', {
        authorityKind: parsed.authorityKind,
        authority: parsed.authority,
        resolvedIpsJson: JSON.stringify(parsed.resolvedIps ?? []),
      });

      hostIdByAuthority.set(parsed.authority, node.id);
      if (created) {
        result.hostsCreated++;
      }
    }

    // ---------------------------------------------------------
    // 2. Upsert services + HOST_SERVICE edges
    // ---------------------------------------------------------
    for (const parsed of parseResult.services) {
      const hostId = hostIdByAuthority.get(parsed.hostAuthority);
      if (!hostId) continue;

      const svcKey = `${hostId}:${parsed.transport}:${parsed.port}`;
      if (serviceIdByKey.has(svcKey)) continue;

      const { node, created } = nodeRepo.upsert(
        'service',
        {
          transport: parsed.transport,
          port: parsed.port,
          appProto: parsed.appProto,
          protoConfidence: parsed.protoConfidence,
          banner: parsed.banner,
          product: parsed.product,
          version: parsed.version,
          state: parsed.state,
        },
        artifactId,
        hostId,
      );

      serviceIdByKey.set(svcKey, node.id);

      // HOST_SERVICE edge
      edgeRepo.upsert('HOST_SERVICE', hostId, node.id, artifactId);

      if (created) {
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
    // 3. Service observations (always create new)
    // ---------------------------------------------------------
    for (const parsed of parseResult.serviceObservations) {
      const hostId = hostIdByAuthority.get(parsed.hostAuthority);
      if (!hostId) continue;

      const svcKey = `${hostId}:${parsed.transport}:${parsed.port}`;
      const serviceId = serviceIdByKey.get(svcKey);
      if (!serviceId) continue;

      const obsNode = nodeRepo.create(
        'svc_observation',
        {
          key: parsed.key,
          value: parsed.value,
          confidence: parsed.confidence,
        },
        artifactId,
      );

      edgeRepo.create('SERVICE_OBSERVATION', serviceId, obsNode.id, artifactId);
      result.serviceObservationsCreated++;
    }

    // ---------------------------------------------------------
    // 4. Upsert HTTP endpoints + SERVICE_ENDPOINT edges
    // ---------------------------------------------------------
    for (const parsed of parseResult.httpEndpoints) {
      const serviceId = resolveServiceId(parsed.hostAuthority, parsed.port);
      if (!serviceId) continue;

      const epKey = `${serviceId}:${parsed.method}:${parsed.path}`;
      if (endpointIdByKey.has(epKey)) continue;

      const { node, created } = nodeRepo.upsert(
        'endpoint',
        {
          baseUri: parsed.baseUri,
          method: parsed.method,
          path: parsed.path,
          statusCode: parsed.statusCode,
          contentLength: parsed.contentLength,
          words: parsed.words,
          lines: parsed.lines,
        },
        artifactId,
        serviceId,
      );

      endpointIdByKey.set(epKey, node.id);

      // SERVICE_ENDPOINT edge
      edgeRepo.upsert('SERVICE_ENDPOINT', serviceId, node.id, artifactId);

      if (created) {
        result.httpEndpointsCreated++;
      }
    }

    // ---------------------------------------------------------
    // 5. Upsert inputs + SERVICE_INPUT edges
    // ---------------------------------------------------------
    for (const parsed of parseResult.inputs) {
      const serviceId = resolveServiceId(parsed.hostAuthority, parsed.port);
      if (!serviceId) continue;

      const inKey = `${serviceId}:${parsed.location}:${parsed.name}`;
      if (inputIdByKey.has(inKey)) continue;

      const { node, created } = nodeRepo.upsert(
        'input',
        {
          location: parsed.location,
          name: parsed.name,
          typeHint: parsed.typeHint,
        },
        undefined,
        serviceId,
      );

      inputIdByKey.set(inKey, node.id);

      // SERVICE_INPUT edge
      edgeRepo.upsert('SERVICE_INPUT', serviceId, node.id);

      if (created) {
        result.inputsCreated++;
      }
    }

    // ---------------------------------------------------------
    // 6. Upsert endpoint_inputs (ENDPOINT_INPUT edges)
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

      const { created } = edgeRepo.upsert('ENDPOINT_INPUT', endpointId, inputId, artifactId);
      if (created) {
        result.endpointInputsCreated++;
      }
    }

    // ---------------------------------------------------------
    // 7. Observations (always create new)
    // ---------------------------------------------------------
    for (const parsed of parseResult.observations) {
      const serviceId = resolveServiceId(parsed.hostAuthority, parsed.port);
      if (!serviceId) continue;

      const inKey = `${serviceId}:${parsed.inputLocation}:${parsed.inputName}`;
      const inputId = inputIdByKey.get(inKey);
      if (!inputId) continue;

      const obsNode = nodeRepo.create(
        'observation',
        {
          rawValue: parsed.rawValue,
          normValue: parsed.normValue,
          source: parsed.source,
          confidence: parsed.confidence,
          observedAt: new Date().toISOString(),
        },
        artifactId,
      );

      edgeRepo.create('INPUT_OBSERVATION', inputId, obsNode.id, artifactId);
      result.observationsCreated++;
    }

    // ---------------------------------------------------------
    // 8. Vulnerabilities (always create new)
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

      const vulnNode = nodeRepo.create(
        'vulnerability',
        {
          vulnType: parsed.vulnType,
          title: parsed.title,
          description: parsed.description,
          severity: parsed.severity,
          confidence: parsed.confidence,
        },
        artifactId,
      );

      vulnIdByTitle.set(parsed.title, vulnNode.id);

      // SERVICE_VULNERABILITY edge
      edgeRepo.create('SERVICE_VULNERABILITY', serviceId, vulnNode.id, artifactId);

      // optional ENDPOINT_VULNERABILITY edge
      if (endpointId) {
        edgeRepo.create('ENDPOINT_VULNERABILITY', endpointId, vulnNode.id, artifactId);
      }

      result.vulnerabilitiesCreated++;
    }

    // ---------------------------------------------------------
    // 9. CVEs (always create new)
    // ---------------------------------------------------------
    for (const parsed of parseResult.cves) {
      const vulnId = vulnIdByTitle.get(parsed.vulnerabilityTitle);
      if (!vulnId) continue;

      const cveNode = nodeRepo.create(
        'cve',
        {
          cveId: parsed.cveId,
          description: parsed.description,
          cvssScore: parsed.cvssScore,
          cvssVector: parsed.cvssVector,
          referenceUrl: parsed.referenceUrl,
        },
        undefined,
        vulnId,
      );

      edgeRepo.create('VULNERABILITY_CVE', vulnId, cveNode.id);
      result.cvesCreated++;
    }

    return result;
  });

  return run();
}
