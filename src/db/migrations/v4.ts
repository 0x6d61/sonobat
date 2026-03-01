/**
 * Migration v4: Graph-native schema
 *
 * 12 エンティティテーブル → nodes + edges の 2 テーブルに移行。
 * 既存データをマイグレーションし、旧テーブルを DROP する。
 */

import type Database from 'better-sqlite3';
import type { Migration } from './index.js';
import { randomUUID } from 'node:crypto';

const migration: Migration = {
  version: 4,
  description: 'Graph-native schema: nodes + edges tables',
  up(db: Database.Database): void {
    // --------------------------------------------------
    // 1. nodes + edges テーブル作成
    // --------------------------------------------------
    db.exec(`
      CREATE TABLE IF NOT EXISTS nodes (
        id                    TEXT PRIMARY KEY,
        kind                  TEXT NOT NULL,
        natural_key           TEXT NOT NULL UNIQUE,
        props_json            TEXT NOT NULL DEFAULT '{}',
        evidence_artifact_id  TEXT REFERENCES artifacts(id),
        created_at            TEXT NOT NULL,
        updated_at            TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);
      CREATE INDEX IF NOT EXISTS idx_nodes_evidence ON nodes(evidence_artifact_id);

      CREATE TABLE IF NOT EXISTS edges (
        id                    TEXT PRIMARY KEY,
        kind                  TEXT NOT NULL,
        source_id             TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        target_id             TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        props_json            TEXT NOT NULL DEFAULT '{}',
        evidence_artifact_id  TEXT REFERENCES artifacts(id),
        created_at            TEXT NOT NULL,
        UNIQUE(kind, source_id, target_id)
      );
      CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_id);
      CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_id);
      CREATE INDEX IF NOT EXISTS idx_edges_kind ON edges(kind);
    `);

    // --------------------------------------------------
    // 2. 既存データのマイグレーション
    // --------------------------------------------------

    // ヘルパー: edge 挿入
    const insertEdge = db.prepare(`
      INSERT INTO edges (id, kind, source_id, target_id, props_json, evidence_artifact_id, created_at)
      VALUES (?, ?, ?, ?, '{}', ?, ?)
    `);

    const insertNode = db.prepare(`
      INSERT INTO nodes (id, kind, natural_key, props_json, evidence_artifact_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    // テーブル存在チェック
    const tableExists = (name: string): boolean => {
      const row = db
        .prepare("SELECT COUNT(*) AS cnt FROM sqlite_master WHERE type='table' AND name=?")
        .get(name) as { cnt: number };
      return row.cnt > 0;
    };

    // 2a. hosts → nodes (kind="host")
    if (tableExists('hosts')) {
      const hosts = db.prepare('SELECT * FROM hosts').all() as Array<Record<string, unknown>>;
      for (const h of hosts) {
        const props = JSON.stringify({
          authorityKind: h.authority_kind,
          authority: h.authority,
          resolvedIpsJson: h.resolved_ips_json ?? '[]',
        });
        insertNode.run(
          h.id,
          'host',
          `host:${h.authority}`,
          props,
          null, // hosts didn't have evidence_artifact_id
          h.created_at,
          h.updated_at,
        );
      }
    }

    // 2b. vhosts → nodes (kind="vhost") + edge (HOST_VHOST)
    if (tableExists('vhosts')) {
      const vhosts = db.prepare('SELECT * FROM vhosts').all() as Array<Record<string, unknown>>;
      for (const v of vhosts) {
        const props = JSON.stringify({
          hostname: v.hostname,
          source: v.source ?? undefined,
        });
        insertNode.run(
          v.id,
          'vhost',
          `vhost:${v.host_id}:${v.hostname}`,
          props,
          v.evidence_artifact_id,
          v.created_at,
          v.created_at, // vhosts had no updated_at
        );
        insertEdge.run(
          randomUUID(),
          'HOST_VHOST',
          v.host_id,
          v.id,
          v.evidence_artifact_id,
          v.created_at,
        );
      }
    }

    // 2c. services → nodes (kind="service") + edge (HOST_SERVICE)
    if (tableExists('services')) {
      const services = db.prepare('SELECT * FROM services').all() as Array<Record<string, unknown>>;
      for (const s of services) {
        const props = JSON.stringify({
          transport: s.transport,
          port: s.port,
          appProto: s.app_proto,
          protoConfidence: s.proto_confidence,
          banner: s.banner ?? undefined,
          product: s.product ?? undefined,
          version: s.version ?? undefined,
          state: s.state,
        });
        insertNode.run(
          s.id,
          'service',
          `svc:${s.host_id}:${s.transport}:${s.port}`,
          props,
          s.evidence_artifact_id,
          s.created_at,
          s.updated_at,
        );
        insertEdge.run(
          randomUUID(),
          'HOST_SERVICE',
          s.host_id,
          s.id,
          s.evidence_artifact_id,
          s.created_at,
        );
      }
    }

    // 2d. service_observations → nodes (kind="svc_observation") + edge (SERVICE_OBSERVATION)
    if (tableExists('service_observations')) {
      const svcObs = db.prepare('SELECT * FROM service_observations').all() as Array<
        Record<string, unknown>
      >;
      for (const so of svcObs) {
        const props = JSON.stringify({
          key: so.key,
          value: so.value,
          confidence: so.confidence,
        });
        insertNode.run(
          so.id,
          'svc_observation',
          `svcobs:${so.id}`,
          props,
          so.evidence_artifact_id,
          so.created_at,
          so.created_at, // no updated_at
        );
        insertEdge.run(
          randomUUID(),
          'SERVICE_OBSERVATION',
          so.service_id,
          so.id,
          so.evidence_artifact_id,
          so.created_at,
        );
      }
    }

    // 2e. http_endpoints → nodes (kind="endpoint") + edge (SERVICE_ENDPOINT) + optional (VHOST_ENDPOINT)
    if (tableExists('http_endpoints')) {
      const endpoints = db.prepare('SELECT * FROM http_endpoints').all() as Array<
        Record<string, unknown>
      >;
      for (const ep of endpoints) {
        const props = JSON.stringify({
          baseUri: ep.base_uri,
          method: ep.method,
          path: ep.path,
          statusCode: ep.status_code ?? undefined,
          contentLength: ep.content_length ?? undefined,
          words: ep.words ?? undefined,
          lines: ep.lines ?? undefined,
        });
        insertNode.run(
          ep.id,
          'endpoint',
          `ep:${ep.service_id}:${ep.method}:${ep.path}`,
          props,
          ep.evidence_artifact_id,
          ep.created_at,
          ep.created_at, // no updated_at
        );
        insertEdge.run(
          randomUUID(),
          'SERVICE_ENDPOINT',
          ep.service_id,
          ep.id,
          ep.evidence_artifact_id,
          ep.created_at,
        );
        // Optional: VHOST_ENDPOINT
        if (ep.vhost_id) {
          insertEdge.run(
            randomUUID(),
            'VHOST_ENDPOINT',
            ep.vhost_id,
            ep.id,
            ep.evidence_artifact_id,
            ep.created_at,
          );
        }
      }
    }

    // 2f. inputs → nodes (kind="input") + edge (SERVICE_INPUT)
    if (tableExists('inputs')) {
      const inputs = db.prepare('SELECT * FROM inputs').all() as Array<Record<string, unknown>>;
      for (const inp of inputs) {
        const props = JSON.stringify({
          location: inp.location,
          name: inp.name,
          typeHint: inp.type_hint ?? undefined,
        });
        insertNode.run(
          inp.id,
          'input',
          `in:${inp.service_id}:${inp.location}:${inp.name}`,
          props,
          null, // inputs had no evidence_artifact_id
          inp.created_at,
          inp.updated_at,
        );
        insertEdge.run(randomUUID(), 'SERVICE_INPUT', inp.service_id, inp.id, null, inp.created_at);
      }
    }

    // 2g. endpoint_inputs → edges (ENDPOINT_INPUT)
    if (tableExists('endpoint_inputs')) {
      const epInputs = db.prepare('SELECT * FROM endpoint_inputs').all() as Array<
        Record<string, unknown>
      >;
      for (const ei of epInputs) {
        insertEdge.run(
          ei.id,
          'ENDPOINT_INPUT',
          ei.endpoint_id,
          ei.input_id,
          ei.evidence_artifact_id,
          ei.created_at,
        );
      }
    }

    // 2h. observations → nodes (kind="observation") + edge (INPUT_OBSERVATION)
    if (tableExists('observations')) {
      const obs = db.prepare('SELECT * FROM observations').all() as Array<Record<string, unknown>>;
      for (const o of obs) {
        const props = JSON.stringify({
          rawValue: o.raw_value,
          normValue: o.norm_value,
          bodyPath: o.body_path ?? undefined,
          source: o.source,
          confidence: o.confidence,
          observedAt: o.observed_at,
        });
        insertNode.run(
          o.id,
          'observation',
          `obs:${o.id}`,
          props,
          o.evidence_artifact_id,
          o.observed_at,
          o.observed_at, // no updated_at
        );
        insertEdge.run(
          randomUUID(),
          'INPUT_OBSERVATION',
          o.input_id,
          o.id,
          o.evidence_artifact_id,
          o.observed_at,
        );
      }
    }

    // 2i. credentials → nodes (kind="credential") + edge (SERVICE_CREDENTIAL) + optional (ENDPOINT_CREDENTIAL)
    if (tableExists('credentials')) {
      const creds = db.prepare('SELECT * FROM credentials').all() as Array<Record<string, unknown>>;
      for (const c of creds) {
        const props = JSON.stringify({
          username: c.username,
          secret: c.secret,
          secretType: c.secret_type,
          source: c.source,
          confidence: c.confidence,
        });
        insertNode.run(
          c.id,
          'credential',
          `cred:${c.id}`,
          props,
          c.evidence_artifact_id,
          c.created_at,
          c.created_at, // no updated_at
        );
        insertEdge.run(
          randomUUID(),
          'SERVICE_CREDENTIAL',
          c.service_id,
          c.id,
          c.evidence_artifact_id,
          c.created_at,
        );
        if (c.endpoint_id) {
          insertEdge.run(
            randomUUID(),
            'ENDPOINT_CREDENTIAL',
            c.endpoint_id,
            c.id,
            c.evidence_artifact_id,
            c.created_at,
          );
        }
      }
    }

    // 2j. vulnerabilities → nodes (kind="vulnerability") + edge (SERVICE_VULNERABILITY) + optional (ENDPOINT_VULNERABILITY)
    if (tableExists('vulnerabilities')) {
      const vulns = db.prepare('SELECT * FROM vulnerabilities').all() as Array<
        Record<string, unknown>
      >;
      for (const v of vulns) {
        const props = JSON.stringify({
          vulnType: v.vuln_type,
          title: v.title,
          description: v.description ?? undefined,
          severity: v.severity,
          confidence: v.confidence,
          status: v.status ?? 'unverified',
        });
        insertNode.run(
          v.id,
          'vulnerability',
          `vuln:${v.id}`,
          props,
          v.evidence_artifact_id,
          v.created_at,
          v.created_at, // no updated_at
        );
        insertEdge.run(
          randomUUID(),
          'SERVICE_VULNERABILITY',
          v.service_id,
          v.id,
          v.evidence_artifact_id,
          v.created_at,
        );
        if (v.endpoint_id) {
          insertEdge.run(
            randomUUID(),
            'ENDPOINT_VULNERABILITY',
            v.endpoint_id,
            v.id,
            v.evidence_artifact_id,
            v.created_at,
          );
        }
      }
    }

    // 2k. cves → nodes (kind="cve") + edge (VULNERABILITY_CVE)
    if (tableExists('cves')) {
      const cves = db.prepare('SELECT * FROM cves').all() as Array<Record<string, unknown>>;
      for (const c of cves) {
        const props = JSON.stringify({
          cveId: c.cve_id,
          description: c.description ?? undefined,
          cvssScore: c.cvss_score ?? undefined,
          cvssVector: c.cvss_vector ?? undefined,
          referenceUrl: c.reference_url ?? undefined,
        });
        insertNode.run(
          c.id,
          'cve',
          `cve:${c.vulnerability_id}:${c.cve_id}`,
          props,
          null, // cves had no evidence_artifact_id
          c.created_at,
          c.created_at, // no updated_at
        );
        insertEdge.run(
          randomUUID(),
          'VULNERABILITY_CVE',
          c.vulnerability_id,
          c.id,
          null,
          c.created_at,
        );
      }
    }

    // --------------------------------------------------
    // 3. 旧テーブル DROP
    //    FK 依存順に削除（子テーブルから親テーブルへ）
    // --------------------------------------------------
    // FK を一時的に無効化して DROP
    db.pragma('foreign_keys = OFF');

    const tablesToDrop = [
      'endpoint_inputs',
      'observations',
      'credentials',
      'cves',
      'vulnerabilities',
      'http_endpoints',
      'service_observations',
      'inputs',
      'services',
      'vhosts',
      'hosts',
      'datalog_rules',
    ];

    for (const table of tablesToDrop) {
      if (tableExists(table)) {
        db.exec(`DROP TABLE ${table}`);
      }
    }

    // FK を再度有効化
    db.pragma('foreign_keys = ON');
  },
};

export default migration;
