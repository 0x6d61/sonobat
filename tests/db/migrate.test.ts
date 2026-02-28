import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../src/db/migrate.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

/** テスト用の ISO 8601 タイムスタンプを返す */
function now(): string {
  return new Date().toISOString();
}

/** テスト用の UUID を返す */
function uuid(): string {
  return crypto.randomUUID();
}

/** sqlite_master からテーブル名一覧を取得する */
function tableNames(db: InstanceType<typeof Database>): string[] {
  const rows = db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    .all() as Array<{ name: string }>;
  return rows.map((r) => r.name).sort();
}

/** sqlite_master からインデックス名一覧を取得する */
function indexNames(db: InstanceType<typeof Database>): string[] {
  const rows = db
    .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")
    .all() as Array<{ name: string }>;
  return rows.map((r) => r.name).sort();
}

/** PRAGMA user_version を取得する */
function getUserVersion(db: InstanceType<typeof Database>): number {
  const row = db.prepare('PRAGMA user_version').get() as {
    user_version: number;
  };
  return row.user_version;
}

// ---------------------------------------------------------------------------
// 共通フィクスチャ挿入ヘルパー
// ---------------------------------------------------------------------------

interface InsertedHost {
  hostId: string;
}

function insertHost(db: InstanceType<typeof Database>, authority = '10.0.0.1'): InsertedHost {
  const hostId = uuid();
  const ts = now();
  db.prepare(
    `INSERT INTO hosts (id, authority_kind, authority, created_at, updated_at)
     VALUES (?, 'IP', ?, ?, ?)`,
  ).run(hostId, authority, ts, ts);
  return { hostId };
}

interface InsertedArtifact {
  artifactId: string;
}

function insertArtifact(
  db: InstanceType<typeof Database>,
  scanId: string | null = null,
): InsertedArtifact {
  const artifactId = uuid();
  db.prepare(
    `INSERT INTO artifacts (id, scan_id, tool, kind, path, captured_at)
     VALUES (?, ?, 'nmap', 'tool_output', '/tmp/scan.xml', ?)`,
  ).run(artifactId, scanId, now());
  return { artifactId };
}

interface InsertedService {
  serviceId: string;
}

function insertService(
  db: InstanceType<typeof Database>,
  hostId: string,
  artifactId: string,
  overrides: { transport?: string; port?: number } = {},
): InsertedService {
  const serviceId = uuid();
  const ts = now();
  db.prepare(
    `INSERT INTO services
       (id, host_id, transport, port, app_proto, proto_confidence, state, evidence_artifact_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'http', 'high', 'open', ?, ?, ?)`,
  ).run(serviceId, hostId, overrides.transport ?? 'tcp', overrides.port ?? 80, artifactId, ts, ts);
  return { serviceId };
}

interface InsertedEndpoint {
  endpointId: string;
}

function insertEndpoint(
  db: InstanceType<typeof Database>,
  serviceId: string,
  artifactId: string,
  overrides: { method?: string; path?: string } = {},
): InsertedEndpoint {
  const endpointId = uuid();
  db.prepare(
    `INSERT INTO http_endpoints
       (id, service_id, base_uri, method, path, evidence_artifact_id, created_at)
     VALUES (?, ?, 'http://10.0.0.1:80', ?, ?, ?, ?)`,
  ).run(endpointId, serviceId, overrides.method ?? 'GET', overrides.path ?? '/', artifactId, now());
  return { endpointId };
}

interface InsertedInput {
  inputId: string;
}

function insertInput(
  db: InstanceType<typeof Database>,
  serviceId: string,
  overrides: { location?: string; name?: string } = {},
): InsertedInput {
  const inputId = uuid();
  const ts = now();
  db.prepare(
    `INSERT INTO inputs (id, service_id, location, name, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(inputId, serviceId, overrides.location ?? 'query', overrides.name ?? 'id', ts, ts);
  return { inputId };
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('migrateDatabase', () => {
  let db: InstanceType<typeof Database>;

  beforeEach(() => {
    db = new Database(':memory:');
  });

  // 1
  it('全テーブルが作成される', () => {
    migrateDatabase(db);

    const tables = tableNames(db);

    const expected = [
      'artifacts',
      'credentials',
      'cves',
      'datalog_rules',
      'endpoint_inputs',
      'hosts',
      'http_endpoints',
      'inputs',
      'observations',
      'scans',
      'service_observations',
      'services',
      'vhosts',
      'vulnerabilities',
    ].sort();

    expect(tables).toEqual(expected);
  });

  // 2
  it('外部キー制約が有効', () => {
    migrateDatabase(db);

    const row = db.prepare('PRAGMA foreign_keys').get() as {
      foreign_keys: number;
    };
    expect(row.foreign_keys).toBe(1);
  });

  // 3
  it('hosts テーブルに UNIQUE 制約がある', () => {
    migrateDatabase(db);

    insertHost(db, '10.0.0.1');

    expect(() => {
      insertHost(db, '10.0.0.1');
    }).toThrow(/UNIQUE/);
  });

  // 4
  it('services テーブルに UNIQUE 制約がある (host_id, transport, port)', () => {
    migrateDatabase(db);

    const { hostId } = insertHost(db);
    const { artifactId } = insertArtifact(db);

    insertService(db, hostId, artifactId, { transport: 'tcp', port: 80 });

    expect(() => {
      insertService(db, hostId, artifactId, { transport: 'tcp', port: 80 });
    }).toThrow(/UNIQUE/);
  });

  // 5
  it('FK CASCADE: hosts 削除で services も削除される', () => {
    migrateDatabase(db);

    const { hostId } = insertHost(db);
    const { artifactId } = insertArtifact(db);
    const { serviceId } = insertService(db, hostId, artifactId);

    // host を削除
    db.prepare('DELETE FROM hosts WHERE id = ?').run(hostId);

    // service も CASCADE で消えていること
    const row = db.prepare('SELECT COUNT(*) AS cnt FROM services WHERE id = ?').get(serviceId) as {
      cnt: number;
    };
    expect(row.cnt).toBe(0);
  });

  // 6
  it('FK RESTRICT: artifact 参照中のサービスがある場合 artifact は削除できない', () => {
    migrateDatabase(db);

    const { hostId } = insertHost(db);
    const { artifactId } = insertArtifact(db);
    insertService(db, hostId, artifactId);

    // artifact を消そうとすると RESTRICT で失敗する
    expect(() => {
      db.prepare('DELETE FROM artifacts WHERE id = ?').run(artifactId);
    }).toThrow(/FOREIGN KEY/);
  });

  // 7
  it('inputs の UNIQUE 制約 (service_id, location, name)', () => {
    migrateDatabase(db);

    const { hostId } = insertHost(db);
    const { artifactId } = insertArtifact(db);
    const { serviceId } = insertService(db, hostId, artifactId);

    insertInput(db, serviceId, { location: 'query', name: 'id' });

    expect(() => {
      insertInput(db, serviceId, { location: 'query', name: 'id' });
    }).toThrow(/UNIQUE/);
  });

  // 8
  it('endpoint_inputs の UNIQUE 制約 (endpoint_id, input_id)', () => {
    migrateDatabase(db);

    const { hostId } = insertHost(db);
    const { artifactId } = insertArtifact(db);
    const { serviceId } = insertService(db, hostId, artifactId);
    const { endpointId } = insertEndpoint(db, serviceId, artifactId);
    const { inputId } = insertInput(db, serviceId);

    const ts = now();

    db.prepare(
      `INSERT INTO endpoint_inputs (id, endpoint_id, input_id, evidence_artifact_id, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(uuid(), endpointId, inputId, artifactId, ts);

    expect(() => {
      db.prepare(
        `INSERT INTO endpoint_inputs (id, endpoint_id, input_id, evidence_artifact_id, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).run(uuid(), endpointId, inputId, artifactId, ts);
    }).toThrow(/UNIQUE/);
  });

  // 9
  it('credentials が service レベルでも endpoint レベルでも紐づけ可能', () => {
    migrateDatabase(db);

    const { hostId } = insertHost(db);
    const { artifactId } = insertArtifact(db);
    const { serviceId } = insertService(db, hostId, artifactId);
    const { endpointId } = insertEndpoint(db, serviceId, artifactId);

    const credServiceLevel = uuid();
    const credEndpointLevel = uuid();
    const ts = now();

    // service レベル（SSH 等）— endpoint_id = null
    db.prepare(
      `INSERT INTO credentials
         (id, service_id, endpoint_id, username, secret, secret_type, source, confidence, evidence_artifact_id, created_at)
       VALUES (?, ?, NULL, 'admin', 'password123', 'password', 'default', 'high', ?, ?)`,
    ).run(credServiceLevel, serviceId, artifactId, ts);

    // endpoint レベル（HTTP ログイン等）— endpoint_id を指定
    db.prepare(
      `INSERT INTO credentials
         (id, service_id, endpoint_id, username, secret, secret_type, source, confidence, evidence_artifact_id, created_at)
       VALUES (?, ?, ?, 'admin', 'token-abc', 'token', 'manual', 'medium', ?, ?)`,
    ).run(credEndpointLevel, serviceId, endpointId, artifactId, ts);

    // 両方取得できること
    const rows = db
      .prepare('SELECT id, endpoint_id FROM credentials WHERE service_id = ? ORDER BY id')
      .all(serviceId) as Array<{ id: string; endpoint_id: string | null }>;

    expect(rows).toHaveLength(2);

    const serviceLevelRow = rows.find((r) => r.id === credServiceLevel);
    const endpointLevelRow = rows.find((r) => r.id === credEndpointLevel);

    expect(serviceLevelRow).toBeDefined();
    expect(serviceLevelRow!.endpoint_id).toBeNull();

    expect(endpointLevelRow).toBeDefined();
    expect(endpointLevelRow!.endpoint_id).toBe(endpointId);
  });

  // 10
  it('vulnerabilities -> cves の CASCADE 削除', () => {
    migrateDatabase(db);

    const { hostId } = insertHost(db);
    const { artifactId } = insertArtifact(db);
    const { serviceId } = insertService(db, hostId, artifactId);

    const vulnId = uuid();
    const cveRowId = uuid();
    const ts = now();

    db.prepare(
      `INSERT INTO vulnerabilities
         (id, service_id, vuln_type, title, severity, confidence, evidence_artifact_id, created_at)
       VALUES (?, ?, 'sqli', 'SQL Injection in login', 'critical', 'high', ?, ?)`,
    ).run(vulnId, serviceId, artifactId, ts);

    db.prepare(
      `INSERT INTO cves
         (id, vulnerability_id, cve_id, description, created_at)
       VALUES (?, ?, 'CVE-2024-12345', 'Test CVE', ?)`,
    ).run(cveRowId, vulnId, ts);

    // vulnerability を削除
    db.prepare('DELETE FROM vulnerabilities WHERE id = ?').run(vulnId);

    // cve も CASCADE で消えること
    const row = db.prepare('SELECT COUNT(*) AS cnt FROM cves WHERE id = ?').get(cveRowId) as {
      cnt: number;
    };
    expect(row.cnt).toBe(0);
  });

  // 11
  it('vhosts の UNIQUE 制約 (host_id, hostname)', () => {
    migrateDatabase(db);

    const { hostId } = insertHost(db);
    const { artifactId } = insertArtifact(db);

    const ts = now();

    db.prepare(
      `INSERT INTO vhosts (id, host_id, hostname, source, evidence_artifact_id, created_at)
       VALUES (?, ?, 'example.com', 'nmap', ?, ?)`,
    ).run(uuid(), hostId, artifactId, ts);

    expect(() => {
      db.prepare(
        `INSERT INTO vhosts (id, host_id, hostname, source, evidence_artifact_id, created_at)
         VALUES (?, ?, 'example.com', 'cert', ?, ?)`,
      ).run(uuid(), hostId, artifactId, ts);
    }).toThrow(/UNIQUE/);
  });

  // 12
  it('インデックスが作成される', () => {
    migrateDatabase(db);

    const indexes = indexNames(db);

    const expectedIndexes = [
      'idx_artifacts_tool',
      'idx_creds_endpoint',
      'idx_creds_service',
      'idx_cves_cveid',
      'idx_cves_vuln',
      'idx_datalog_rules_name',
      'idx_endpoints_service',
      'idx_ep_inputs_endpoint',
      'idx_ep_inputs_input',
      'idx_inputs_service',
      'idx_obs_input',
      'idx_services_host',
      'idx_svc_obs_service',
      'idx_vhosts_host',
      'idx_vulns_endpoint',
      'idx_vulns_service',
      'idx_vulns_severity',
    ];

    for (const idx of expectedIndexes) {
      expect(indexes).toContain(idx);
    }
  });

  // --- マイグレーションシステムのテスト ---

  // 13
  it('新規 DB で user_version が最新バージョンに設定される', () => {
    migrateDatabase(db);

    const version = getUserVersion(db);
    expect(version).toBeGreaterThanOrEqual(1);
  });

  // 14
  it('2回実行しても冪等（既にマイグレーション済みなら何もしない）', () => {
    migrateDatabase(db);
    const v1 = getUserVersion(db);

    // 2回目の実行
    migrateDatabase(db);
    const v2 = getUserVersion(db);

    expect(v2).toBe(v1);

    // テーブルも壊れていない
    const tables = tableNames(db);
    expect(tables).toContain('hosts');
    expect(tables).toContain('datalog_rules');
  });

  // 15
  it('既存 v1 DB（user_version=1）から v2 マイグレーションで status カラムが追加される', () => {
    // v1 相当のスキーマを手動で作成（status カラムなし）
    db.pragma('foreign_keys = ON');
    db.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, notes TEXT
      );
      CREATE TABLE IF NOT EXISTS artifacts (
        id TEXT PRIMARY KEY, scan_id TEXT, tool TEXT NOT NULL, kind TEXT NOT NULL,
        path TEXT NOT NULL, sha256 TEXT, captured_at TEXT NOT NULL, attrs_json TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_artifacts_tool ON artifacts(tool);
      CREATE TABLE IF NOT EXISTS hosts (
        id TEXT PRIMARY KEY, authority_kind TEXT NOT NULL, authority TEXT NOT NULL UNIQUE,
        resolved_ips_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS vhosts (
        id TEXT PRIMARY KEY, host_id TEXT NOT NULL, hostname TEXT NOT NULL,
        source TEXT, evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE (host_id, hostname),
        FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_vhosts_host ON vhosts(host_id);
      CREATE TABLE IF NOT EXISTS services (
        id TEXT PRIMARY KEY, host_id TEXT NOT NULL, transport TEXT NOT NULL,
        port INTEGER NOT NULL, app_proto TEXT NOT NULL, proto_confidence TEXT NOT NULL,
        banner TEXT, product TEXT, version TEXT, state TEXT NOT NULL,
        evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        UNIQUE (host_id, transport, port),
        FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
      CREATE TABLE IF NOT EXISTS service_observations (
        id TEXT PRIMARY KEY, service_id TEXT NOT NULL, key TEXT NOT NULL,
        value TEXT NOT NULL, confidence TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_svc_obs_service ON service_observations(service_id);
      CREATE TABLE IF NOT EXISTS http_endpoints (
        id TEXT PRIMARY KEY, service_id TEXT NOT NULL, vhost_id TEXT,
        base_uri TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
        status_code INTEGER, content_length INTEGER, words INTEGER, lines INTEGER,
        evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE (service_id, method, path),
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
        FOREIGN KEY (vhost_id) REFERENCES vhosts(id) ON DELETE SET NULL,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_endpoints_service ON http_endpoints(service_id);
      CREATE TABLE IF NOT EXISTS inputs (
        id TEXT PRIMARY KEY, service_id TEXT NOT NULL, location TEXT NOT NULL,
        name TEXT NOT NULL, type_hint TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        UNIQUE (service_id, location, name),
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_inputs_service ON inputs(service_id);
      CREATE TABLE IF NOT EXISTS endpoint_inputs (
        id TEXT PRIMARY KEY, endpoint_id TEXT NOT NULL, input_id TEXT NOT NULL,
        evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE (endpoint_id, input_id),
        FOREIGN KEY (endpoint_id) REFERENCES http_endpoints(id) ON DELETE CASCADE,
        FOREIGN KEY (input_id) REFERENCES inputs(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_ep_inputs_endpoint ON endpoint_inputs(endpoint_id);
      CREATE INDEX IF NOT EXISTS idx_ep_inputs_input ON endpoint_inputs(input_id);
      CREATE TABLE IF NOT EXISTS observations (
        id TEXT PRIMARY KEY, input_id TEXT NOT NULL, raw_value TEXT NOT NULL,
        norm_value TEXT NOT NULL, body_path TEXT, source TEXT NOT NULL,
        confidence TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL, observed_at TEXT NOT NULL,
        FOREIGN KEY (input_id) REFERENCES inputs(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_obs_input ON observations(input_id);
      CREATE TABLE IF NOT EXISTS credentials (
        id TEXT PRIMARY KEY, service_id TEXT NOT NULL, endpoint_id TEXT,
        username TEXT NOT NULL, secret TEXT NOT NULL, secret_type TEXT NOT NULL,
        source TEXT NOT NULL, confidence TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
        FOREIGN KEY (endpoint_id) REFERENCES http_endpoints(id) ON DELETE SET NULL,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_creds_service ON credentials(service_id);
      CREATE INDEX IF NOT EXISTS idx_creds_endpoint ON credentials(endpoint_id);
      CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY, service_id TEXT NOT NULL, endpoint_id TEXT,
        vuln_type TEXT NOT NULL, title TEXT NOT NULL, description TEXT,
        severity TEXT NOT NULL, confidence TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
        FOREIGN KEY (endpoint_id) REFERENCES http_endpoints(id) ON DELETE SET NULL,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_vulns_service ON vulnerabilities(service_id);
      CREATE INDEX IF NOT EXISTS idx_vulns_endpoint ON vulnerabilities(endpoint_id);
      CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
      CREATE TABLE IF NOT EXISTS cves (
        id TEXT PRIMARY KEY, vulnerability_id TEXT NOT NULL, cve_id TEXT NOT NULL,
        description TEXT, cvss_score REAL, cvss_vector TEXT, reference_url TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_cves_vuln ON cves(vulnerability_id);
      CREATE INDEX IF NOT EXISTS idx_cves_cveid ON cves(cve_id);
      CREATE TABLE IF NOT EXISTS datalog_rules (
        id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT,
        rule_text TEXT NOT NULL, generated_by TEXT NOT NULL,
        is_preset INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_datalog_rules_name ON datalog_rules(name);
    `);
    db.pragma('user_version = 1');

    // 既存データを挿入（status カラムなし）
    const { hostId } = insertHost(db);
    const { artifactId } = insertArtifact(db);
    const { serviceId } = insertService(db, hostId, artifactId);

    const vulnId = uuid();
    db.prepare(
      `INSERT INTO vulnerabilities
         (id, service_id, vuln_type, title, severity, confidence, evidence_artifact_id, created_at)
       VALUES (?, ?, 'sqli', 'SQL Injection', 'critical', 'high', ?, ?)`,
    ).run(vulnId, serviceId, artifactId, now());

    expect(getUserVersion(db)).toBe(1);

    // v2 マイグレーションを実行
    migrateDatabase(db);

    // user_version が 2 以上に更新される
    expect(getUserVersion(db)).toBeGreaterThanOrEqual(2);

    // 既存レコードの status がデフォルト値 'unverified' になっている
    const row = db.prepare('SELECT status FROM vulnerabilities WHERE id = ?').get(vulnId) as {
      status: string;
    };
    expect(row.status).toBe('unverified');

    // 新規レコードもデフォルト値 'unverified' で挿入される
    const newVulnId = uuid();
    db.prepare(
      `INSERT INTO vulnerabilities
         (id, service_id, vuln_type, title, severity, confidence, evidence_artifact_id, created_at)
       VALUES (?, ?, 'xss', 'XSS', 'high', 'medium', ?, ?)`,
    ).run(newVulnId, serviceId, artifactId, now());

    const newRow = db.prepare('SELECT status FROM vulnerabilities WHERE id = ?').get(newVulnId) as {
      status: string;
    };
    expect(newRow.status).toBe('unverified');
  });

  // 16
  it('既存 v0 DB（user_version=0、datalog_rules なし）からマイグレーションできる', () => {
    // v0 の状態を再現: datalog_rules テーブルなしでスキーマを作成
    db.pragma('foreign_keys = ON');
    db.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, notes TEXT
      );
      CREATE TABLE IF NOT EXISTS artifacts (
        id TEXT PRIMARY KEY, scan_id TEXT, tool TEXT NOT NULL, kind TEXT NOT NULL,
        path TEXT NOT NULL, sha256 TEXT, captured_at TEXT NOT NULL, attrs_json TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_artifacts_tool ON artifacts(tool);
      CREATE TABLE IF NOT EXISTS hosts (
        id TEXT PRIMARY KEY, authority_kind TEXT NOT NULL, authority TEXT NOT NULL UNIQUE,
        resolved_ips_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS vhosts (
        id TEXT PRIMARY KEY, host_id TEXT NOT NULL, hostname TEXT NOT NULL,
        source TEXT, evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE (host_id, hostname),
        FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_vhosts_host ON vhosts(host_id);
      CREATE TABLE IF NOT EXISTS services (
        id TEXT PRIMARY KEY, host_id TEXT NOT NULL, transport TEXT NOT NULL,
        port INTEGER NOT NULL, app_proto TEXT NOT NULL, proto_confidence TEXT NOT NULL,
        banner TEXT, product TEXT, version TEXT, state TEXT NOT NULL,
        evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        UNIQUE (host_id, transport, port),
        FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
      CREATE TABLE IF NOT EXISTS service_observations (
        id TEXT PRIMARY KEY, service_id TEXT NOT NULL, key TEXT NOT NULL,
        value TEXT NOT NULL, confidence TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_svc_obs_service ON service_observations(service_id);
      CREATE TABLE IF NOT EXISTS http_endpoints (
        id TEXT PRIMARY KEY, service_id TEXT NOT NULL, vhost_id TEXT,
        base_uri TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
        status_code INTEGER, content_length INTEGER, words INTEGER, lines INTEGER,
        evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE (service_id, method, path),
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
        FOREIGN KEY (vhost_id) REFERENCES vhosts(id) ON DELETE SET NULL,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_endpoints_service ON http_endpoints(service_id);
      CREATE TABLE IF NOT EXISTS inputs (
        id TEXT PRIMARY KEY, service_id TEXT NOT NULL, location TEXT NOT NULL,
        name TEXT NOT NULL, type_hint TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        UNIQUE (service_id, location, name),
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_inputs_service ON inputs(service_id);
      CREATE TABLE IF NOT EXISTS endpoint_inputs (
        id TEXT PRIMARY KEY, endpoint_id TEXT NOT NULL, input_id TEXT NOT NULL,
        evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE (endpoint_id, input_id),
        FOREIGN KEY (endpoint_id) REFERENCES http_endpoints(id) ON DELETE CASCADE,
        FOREIGN KEY (input_id) REFERENCES inputs(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_ep_inputs_endpoint ON endpoint_inputs(endpoint_id);
      CREATE INDEX IF NOT EXISTS idx_ep_inputs_input ON endpoint_inputs(input_id);
      CREATE TABLE IF NOT EXISTS observations (
        id TEXT PRIMARY KEY, input_id TEXT NOT NULL, raw_value TEXT NOT NULL,
        norm_value TEXT NOT NULL, body_path TEXT, source TEXT NOT NULL,
        confidence TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL, observed_at TEXT NOT NULL,
        FOREIGN KEY (input_id) REFERENCES inputs(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_obs_input ON observations(input_id);
      CREATE TABLE IF NOT EXISTS credentials (
        id TEXT PRIMARY KEY, service_id TEXT NOT NULL, endpoint_id TEXT,
        username TEXT NOT NULL, secret TEXT NOT NULL, secret_type TEXT NOT NULL,
        source TEXT NOT NULL, confidence TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
        FOREIGN KEY (endpoint_id) REFERENCES http_endpoints(id) ON DELETE SET NULL,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_creds_service ON credentials(service_id);
      CREATE INDEX IF NOT EXISTS idx_creds_endpoint ON credentials(endpoint_id);
      CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY, service_id TEXT NOT NULL, endpoint_id TEXT,
        vuln_type TEXT NOT NULL, title TEXT NOT NULL, description TEXT,
        severity TEXT NOT NULL, confidence TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
        FOREIGN KEY (endpoint_id) REFERENCES http_endpoints(id) ON DELETE SET NULL,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_vulns_service ON vulnerabilities(service_id);
      CREATE INDEX IF NOT EXISTS idx_vulns_endpoint ON vulnerabilities(endpoint_id);
      CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
      CREATE TABLE IF NOT EXISTS cves (
        id TEXT PRIMARY KEY, vulnerability_id TEXT NOT NULL, cve_id TEXT NOT NULL,
        description TEXT, cvss_score REAL, cvss_vector TEXT, reference_url TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_cves_vuln ON cves(vulnerability_id);
      CREATE INDEX IF NOT EXISTS idx_cves_cveid ON cves(cve_id);
    `);

    // 既存データを入れる
    const { hostId } = insertHost(db);

    // user_version は 0（未設定）
    expect(getUserVersion(db)).toBe(0);
    // datalog_rules テーブルは存在しない
    expect(tableNames(db)).not.toContain('datalog_rules');

    // マイグレーション実行
    migrateDatabase(db);

    // datalog_rules テーブルが追加されている
    expect(tableNames(db)).toContain('datalog_rules');
    // user_version が更新されている
    expect(getUserVersion(db)).toBeGreaterThanOrEqual(1);
    // 既存データが残っている
    const row = db.prepare('SELECT COUNT(*) AS cnt FROM hosts WHERE id = ?').get(hostId) as {
      cnt: number;
    };
    expect(row.cnt).toBe(1);
  });
});
