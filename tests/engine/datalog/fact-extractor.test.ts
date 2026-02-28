import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';
import {
  extractFacts,
  extractFactsByPredicate,
} from '../../../src/engine/datalog/fact-extractor.js';

// ---------------------------------------------------------------------------
// ヘルパー: テスト用データ挿入
// ---------------------------------------------------------------------------

function insertArtifact(db: InstanceType<typeof Database>): string {
  const id = 'art-001';
  db.prepare(
    `INSERT INTO artifacts (id, tool, kind, path, captured_at) VALUES (?, ?, ?, ?, ?)`,
  ).run(id, 'nmap', 'tool_output', '/tmp/scan.xml', '2025-01-01T00:00:00Z');
  return id;
}

function insertHost(
  db: InstanceType<typeof Database>,
  _artifactId: string,
): string {
  const id = 'host-001';
  db.prepare(
    `INSERT INTO hosts (id, authority_kind, authority, resolved_ips_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(id, 'IP', '10.0.0.1', '["10.0.0.1"]', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');
  return id;
}

function insertService(
  db: InstanceType<typeof Database>,
  hostId: string,
  artifactId: string,
): string {
  const id = 'svc-001';
  db.prepare(
    `INSERT INTO services (id, host_id, transport, port, app_proto, proto_confidence, state, evidence_artifact_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, hostId, 'tcp', 80, 'http', 'high', 'open', artifactId, '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');
  return id;
}

function insertHttpEndpoint(
  db: InstanceType<typeof Database>,
  serviceId: string,
  artifactId: string,
): string {
  const id = 'ep-001';
  db.prepare(
    `INSERT INTO http_endpoints (id, service_id, base_uri, method, path, status_code, evidence_artifact_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, serviceId, 'http://10.0.0.1:80', 'GET', '/admin', 200, artifactId, '2025-01-01T00:00:00Z');
  return id;
}

function insertInput(
  db: InstanceType<typeof Database>,
  serviceId: string,
): string {
  const id = 'inp-001';
  db.prepare(
    `INSERT INTO inputs (id, service_id, location, name, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(id, serviceId, 'query', 'id', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');
  return id;
}

function insertEndpointInput(
  db: InstanceType<typeof Database>,
  endpointId: string,
  inputId: string,
  artifactId: string,
): string {
  const id = 'ei-001';
  db.prepare(
    `INSERT INTO endpoint_inputs (id, endpoint_id, input_id, evidence_artifact_id, created_at)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(id, endpointId, inputId, artifactId, '2025-01-01T00:00:00Z');
  return id;
}

function insertObservation(
  db: InstanceType<typeof Database>,
  inputId: string,
  artifactId: string,
): string {
  const id = 'obs-001';
  db.prepare(
    `INSERT INTO observations (id, input_id, raw_value, norm_value, source, confidence, evidence_artifact_id, observed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, inputId, '42', '42', 'ffuf_url', 'high', artifactId, '2025-01-01T00:00:00Z');
  return id;
}

function insertCredential(
  db: InstanceType<typeof Database>,
  serviceId: string,
  artifactId: string,
): string {
  const id = 'cred-001';
  db.prepare(
    `INSERT INTO credentials (id, service_id, username, secret, secret_type, source, confidence, evidence_artifact_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, serviceId, 'admin', 'password123', 'password', 'brute_force', 'high', artifactId, '2025-01-01T00:00:00Z');
  return id;
}

function insertVulnerability(
  db: InstanceType<typeof Database>,
  serviceId: string,
  endpointId: string | null,
  artifactId: string,
): string {
  const id = 'vuln-001';
  db.prepare(
    `INSERT INTO vulnerabilities (id, service_id, endpoint_id, vuln_type, title, severity, confidence, evidence_artifact_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, serviceId, endpointId, 'sqli', 'SQL Injection in id param', 'critical', 'high', artifactId, '2025-01-01T00:00:00Z');
  return id;
}

function insertCve(
  db: InstanceType<typeof Database>,
  vulnerabilityId: string,
): string {
  const id = 'cve-rec-001';
  db.prepare(
    `INSERT INTO cves (id, vulnerability_id, cve_id, cvss_score, created_at)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(id, vulnerabilityId, 'CVE-2024-1234', 9.8, '2025-01-01T00:00:00Z');
  return id;
}

function insertVhost(
  db: InstanceType<typeof Database>,
  hostId: string,
  artifactId: string,
): string {
  const id = 'vhost-001';
  db.prepare(
    `INSERT INTO vhosts (id, host_id, hostname, source, evidence_artifact_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(id, hostId, 'www.example.com', 'cert', artifactId, '2025-01-01T00:00:00Z');
  return id;
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('fact-extractor', () => {
  let db: InstanceType<typeof Database>;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
  });

  describe('extractFacts', () => {
    it('空のDBから空のファクト配列を返す', () => {
      const facts = extractFacts(db);
      expect(facts).toEqual([]);
    });

    it('全テーブルからファクトを抽出する', () => {
      const artifactId = insertArtifact(db);
      const hostId = insertHost(db, artifactId);
      const serviceId = insertService(db, hostId, artifactId);
      const endpointId = insertHttpEndpoint(db, serviceId, artifactId);
      const inputId = insertInput(db, serviceId);
      insertEndpointInput(db, endpointId, inputId, artifactId);
      insertObservation(db, inputId, artifactId);
      insertCredential(db, serviceId, artifactId);
      const vulnId = insertVulnerability(db, serviceId, endpointId, artifactId);
      insertCve(db, vulnId);
      insertVhost(db, hostId, artifactId);

      const facts = extractFacts(db);

      // 各 predicate のファクトが存在するか確認
      const predicates = new Set(facts.map((f) => f.predicate));
      expect(predicates).toContain('host');
      expect(predicates).toContain('service');
      expect(predicates).toContain('http_endpoint');
      expect(predicates).toContain('input');
      expect(predicates).toContain('endpoint_input');
      expect(predicates).toContain('observation');
      expect(predicates).toContain('credential');
      expect(predicates).toContain('vulnerability');
      expect(predicates).toContain('vulnerability_endpoint');
      expect(predicates).toContain('cve');
      expect(predicates).toContain('vhost');
    });

    it('host ファクトの値が正しい', () => {
      const artifactId = insertArtifact(db);
      insertHost(db, artifactId);

      const facts = extractFacts(db);
      const hostFacts = facts.filter((f) => f.predicate === 'host');

      expect(hostFacts).toHaveLength(1);
      expect(hostFacts[0].values).toEqual(['host-001', '10.0.0.1', 'IP']);
    });

    it('service ファクトの値が正しい', () => {
      const artifactId = insertArtifact(db);
      const hostId = insertHost(db, artifactId);
      insertService(db, hostId, artifactId);

      const facts = extractFacts(db);
      const svcFacts = facts.filter((f) => f.predicate === 'service');

      expect(svcFacts).toHaveLength(1);
      expect(svcFacts[0].values).toEqual([
        'host-001', 'svc-001', 'tcp', 80, 'http', 'open',
      ]);
    });

    it('http_endpoint ファクトで statusCode が null の場合は 0 を使用する', () => {
      const artifactId = insertArtifact(db);
      const hostId = insertHost(db, artifactId);
      const serviceId = insertService(db, hostId, artifactId);

      // statusCode を null で挿入
      db.prepare(
        `INSERT INTO http_endpoints (id, service_id, base_uri, method, path, status_code, evidence_artifact_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run('ep-null', serviceId, 'http://10.0.0.1:80', 'POST', '/api', null, artifactId, '2025-01-01T00:00:00Z');

      const facts = extractFacts(db);
      const epFacts = facts.filter((f) => f.predicate === 'http_endpoint');

      expect(epFacts).toHaveLength(1);
      expect(epFacts[0].values).toEqual([
        'svc-001', 'ep-null', 'POST', '/api', 0,
      ]);
    });

    it('vulnerability_endpoint ファクトは endpointId が存在する場合のみ生成される', () => {
      const artifactId = insertArtifact(db);
      const hostId = insertHost(db, artifactId);
      const serviceId = insertService(db, hostId, artifactId);
      const endpointId = insertHttpEndpoint(db, serviceId, artifactId);

      // endpointId あり
      insertVulnerability(db, serviceId, endpointId, artifactId);

      // endpointId なし
      db.prepare(
        `INSERT INTO vulnerabilities (id, service_id, endpoint_id, vuln_type, title, severity, confidence, evidence_artifact_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run('vuln-002', serviceId, null, 'xss', 'XSS', 'high', 'medium', artifactId, '2025-01-01T00:00:00Z');

      const facts = extractFacts(db);
      const veFacts = facts.filter((f) => f.predicate === 'vulnerability_endpoint');

      expect(veFacts).toHaveLength(1);
      expect(veFacts[0].values).toEqual(['vuln-001', 'ep-001']);
    });

    it('cve ファクトで cvssScore が null の場合は 0 を使用する', () => {
      const artifactId = insertArtifact(db);
      const hostId = insertHost(db, artifactId);
      const serviceId = insertService(db, hostId, artifactId);
      const vulnId = insertVulnerability(db, serviceId, null, artifactId);

      db.prepare(
        `INSERT INTO cves (id, vulnerability_id, cve_id, cvss_score, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).run('cve-null', vulnId, 'CVE-2024-9999', null, '2025-01-01T00:00:00Z');

      const facts = extractFacts(db);
      const cveFacts = facts.filter((f) => f.predicate === 'cve');

      expect(cveFacts).toHaveLength(1);
      expect(cveFacts[0].values).toEqual(['vuln-001', 'CVE-2024-9999', 0]);
    });

    it('vhost ファクトで source が null の場合は空文字列を使用する', () => {
      const artifactId = insertArtifact(db);
      const hostId = insertHost(db, artifactId);

      db.prepare(
        `INSERT INTO vhosts (id, host_id, hostname, source, evidence_artifact_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).run('vhost-null', hostId, 'api.example.com', null, artifactId, '2025-01-01T00:00:00Z');

      const facts = extractFacts(db);
      const vhostFacts = facts.filter((f) => f.predicate === 'vhost');

      expect(vhostFacts).toHaveLength(1);
      expect(vhostFacts[0].values).toEqual(['host-001', 'vhost-null', 'api.example.com', '']);
    });
  });

  describe('extractFactsByPredicate', () => {
    it('指定した predicate のファクトのみ返す', () => {
      const artifactId = insertArtifact(db);
      const hostId = insertHost(db, artifactId);
      insertService(db, hostId, artifactId);

      const facts = extractFactsByPredicate(db, 'host');

      expect(facts).toHaveLength(1);
      expect(facts[0].predicate).toBe('host');
    });

    it('存在しない predicate を指定すると空配列を返す', () => {
      const artifactId = insertArtifact(db);
      insertHost(db, artifactId);

      const facts = extractFactsByPredicate(db, 'nonexistent');
      expect(facts).toEqual([]);
    });

    it('limit を指定するとファクト数を制限する', () => {
      const artifactId = insertArtifact(db);
      const hostId = insertHost(db, artifactId);
      const serviceId = insertService(db, hostId, artifactId);

      // 複数の http_endpoint を挿入
      db.prepare(
        `INSERT INTO http_endpoints (id, service_id, base_uri, method, path, status_code, evidence_artifact_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run('ep-a', serviceId, 'http://10.0.0.1:80', 'GET', '/a', 200, artifactId, '2025-01-01T00:00:00Z');
      db.prepare(
        `INSERT INTO http_endpoints (id, service_id, base_uri, method, path, status_code, evidence_artifact_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run('ep-b', serviceId, 'http://10.0.0.1:80', 'GET', '/b', 200, artifactId, '2025-01-01T00:00:00Z');
      db.prepare(
        `INSERT INTO http_endpoints (id, service_id, base_uri, method, path, status_code, evidence_artifact_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run('ep-c', serviceId, 'http://10.0.0.1:80', 'GET', '/c', 200, artifactId, '2025-01-01T00:00:00Z');

      const facts = extractFactsByPredicate(db, 'http_endpoint', 2);
      expect(facts).toHaveLength(2);
    });

    it('limit なしで全ファクトを返す', () => {
      const artifactId = insertArtifact(db);
      const hostId = insertHost(db, artifactId);
      const serviceId = insertService(db, hostId, artifactId);

      // 複数の http_endpoint を挿入
      db.prepare(
        `INSERT INTO http_endpoints (id, service_id, base_uri, method, path, status_code, evidence_artifact_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run('ep-a', serviceId, 'http://10.0.0.1:80', 'GET', '/a', 200, artifactId, '2025-01-01T00:00:00Z');
      db.prepare(
        `INSERT INTO http_endpoints (id, service_id, base_uri, method, path, status_code, evidence_artifact_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run('ep-b', serviceId, 'http://10.0.0.1:80', 'GET', '/b', 200, artifactId, '2025-01-01T00:00:00Z');

      const facts = extractFactsByPredicate(db, 'http_endpoint');
      expect(facts).toHaveLength(2);
    });
  });
});
