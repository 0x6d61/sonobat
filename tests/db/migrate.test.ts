import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../src/db/migrate.js';
import { LATEST_VERSION } from '../../src/db/migrations/index.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

function now(): string {
  return new Date().toISOString();
}

function uuid(): string {
  return crypto.randomUUID();
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

function getUserVersion(db: InstanceType<typeof Database>): number {
  const row = db.prepare('PRAGMA user_version').get() as {
    user_version: number;
  };
  return row.user_version;
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('migrateDatabase', () => {
  let db: InstanceType<typeof Database>;

  beforeEach(() => {
    db = new Database(':memory:');
  });

  // --- Fresh DB (v4 graph-native) ---

  it('fresh DB: nodes + edges テーブルが作成される', () => {
    migrateDatabase(db);

    const tables = tableNames(db);
    expect(tables).toContain('nodes');
    expect(tables).toContain('edges');
  });

  it('fresh DB: 残存テーブル (scans, artifacts, technique_docs) が存在する', () => {
    migrateDatabase(db);

    const tables = tableNames(db);
    expect(tables).toContain('scans');
    expect(tables).toContain('artifacts');
    expect(tables).toContain('technique_docs');
  });

  it('fresh DB: 旧エンティティテーブルは存在しない', () => {
    migrateDatabase(db);

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

  it('fresh DB: user_version が LATEST_VERSION に設定される', () => {
    migrateDatabase(db);

    const version = getUserVersion(db);
    expect(version).toBe(LATEST_VERSION);
  });

  it('外部キー制約が有効', () => {
    migrateDatabase(db);

    const row = db.prepare('PRAGMA foreign_keys').get() as {
      foreign_keys: number;
    };
    expect(row.foreign_keys).toBe(1);
  });

  it('2回実行しても冪等', () => {
    migrateDatabase(db);
    const v1 = getUserVersion(db);

    migrateDatabase(db);
    const v2 = getUserVersion(db);

    expect(v2).toBe(v1);

    const tables = tableNames(db);
    expect(tables).toContain('nodes');
    expect(tables).toContain('edges');
  });

  it('nodes の UNIQUE(natural_key) 制約が機能する', () => {
    migrateDatabase(db);

    const ts = now();
    db.prepare(
      `INSERT INTO nodes (id, kind, natural_key, props_json, created_at, updated_at)
       VALUES (?, 'host', 'host:10.0.0.1', '{}', ?, ?)`,
    ).run(uuid(), ts, ts);

    expect(() => {
      db.prepare(
        `INSERT INTO nodes (id, kind, natural_key, props_json, created_at, updated_at)
         VALUES (?, 'host', 'host:10.0.0.1', '{}', ?, ?)`,
      ).run(uuid(), ts, ts);
    }).toThrow(/UNIQUE/);
  });

  it('edges の UNIQUE(kind, source_id, target_id) 制約が機能する', () => {
    migrateDatabase(db);

    const ts = now();
    const hostId = uuid();
    const svcId = uuid();

    db.prepare(
      `INSERT INTO nodes (id, kind, natural_key, props_json, created_at, updated_at)
       VALUES (?, 'host', ?, '{}', ?, ?)`,
    ).run(hostId, `host:${hostId}`, ts, ts);

    db.prepare(
      `INSERT INTO nodes (id, kind, natural_key, props_json, created_at, updated_at)
       VALUES (?, 'service', ?, '{}', ?, ?)`,
    ).run(svcId, `svc:${svcId}`, ts, ts);

    db.prepare(
      `INSERT INTO edges (id, kind, source_id, target_id, props_json, created_at)
       VALUES (?, 'HOST_SERVICE', ?, ?, '{}', ?)`,
    ).run(uuid(), hostId, svcId, ts);

    expect(() => {
      db.prepare(
        `INSERT INTO edges (id, kind, source_id, target_id, props_json, created_at)
         VALUES (?, 'HOST_SERVICE', ?, ?, '{}', ?)`,
      ).run(uuid(), hostId, svcId, ts);
    }).toThrow(/UNIQUE/);
  });

  it('CASCADE 削除: node 削除で関連 edge も削除される', () => {
    migrateDatabase(db);

    const ts = now();
    const hostId = uuid();
    const svcId = uuid();

    db.prepare(
      `INSERT INTO nodes (id, kind, natural_key, props_json, created_at, updated_at)
       VALUES (?, 'host', ?, '{}', ?, ?)`,
    ).run(hostId, `host:${hostId}`, ts, ts);

    db.prepare(
      `INSERT INTO nodes (id, kind, natural_key, props_json, created_at, updated_at)
       VALUES (?, 'service', ?, '{}', ?, ?)`,
    ).run(svcId, `svc:${svcId}`, ts, ts);

    db.prepare(
      `INSERT INTO edges (id, kind, source_id, target_id, props_json, created_at)
       VALUES (?, 'HOST_SERVICE', ?, ?, '{}', ?)`,
    ).run(uuid(), hostId, svcId, ts);

    db.prepare('DELETE FROM nodes WHERE id = ?').run(hostId);

    const cnt = (
      db.prepare('SELECT COUNT(*) AS cnt FROM edges WHERE source_id = ?').get(hostId) as {
        cnt: number;
      }
    ).cnt;
    expect(cnt).toBe(0);
  });

  it('graph インデックスが作成される', () => {
    migrateDatabase(db);

    const indexes = indexNames(db);
    expect(indexes).toContain('idx_nodes_kind');
    expect(indexes).toContain('idx_nodes_evidence');
    expect(indexes).toContain('idx_edges_source');
    expect(indexes).toContain('idx_edges_target');
    expect(indexes).toContain('idx_edges_kind');
  });

  // --- v3 → v4 マイグレーション ---

  it('既存 v3 DB から v4 マイグレーションが正常に実行される', () => {
    // v3 状態の DB をシミュレート
    db.pragma('foreign_keys = ON');

    // v0 base schema を手動作成
    db.exec(`
      CREATE TABLE scans (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, notes TEXT);
      CREATE TABLE artifacts (id TEXT PRIMARY KEY, scan_id TEXT, tool TEXT NOT NULL, kind TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT, captured_at TEXT NOT NULL, attrs_json TEXT, FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL);
      CREATE INDEX idx_artifacts_tool ON artifacts(tool);
      CREATE TABLE hosts (id TEXT PRIMARY KEY, authority_kind TEXT NOT NULL, authority TEXT NOT NULL UNIQUE, resolved_ips_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
      CREATE TABLE vhosts (id TEXT PRIMARY KEY, host_id TEXT NOT NULL, hostname TEXT NOT NULL, source TEXT, evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(host_id, hostname), FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE, FOREIGN KEY(evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT);
      CREATE TABLE services (id TEXT PRIMARY KEY, host_id TEXT NOT NULL, transport TEXT NOT NULL, port INTEGER NOT NULL, app_proto TEXT NOT NULL, proto_confidence TEXT NOT NULL, banner TEXT, product TEXT, version TEXT, state TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(host_id, transport, port), FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE, FOREIGN KEY(evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT);
      CREATE TABLE service_observations (id TEXT PRIMARY KEY, service_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, confidence TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE, FOREIGN KEY(evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT);
      CREATE TABLE http_endpoints (id TEXT PRIMARY KEY, service_id TEXT NOT NULL, vhost_id TEXT, base_uri TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, status_code INTEGER, content_length INTEGER, words INTEGER, lines INTEGER, evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(service_id, method, path), FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE, FOREIGN KEY(evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT);
      CREATE TABLE inputs (id TEXT PRIMARY KEY, service_id TEXT NOT NULL, location TEXT NOT NULL, name TEXT NOT NULL, type_hint TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(service_id, location, name), FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE);
      CREATE TABLE endpoint_inputs (id TEXT PRIMARY KEY, endpoint_id TEXT NOT NULL, input_id TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(endpoint_id, input_id), FOREIGN KEY(endpoint_id) REFERENCES http_endpoints(id) ON DELETE CASCADE, FOREIGN KEY(input_id) REFERENCES inputs(id) ON DELETE CASCADE, FOREIGN KEY(evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT);
      CREATE TABLE observations (id TEXT PRIMARY KEY, input_id TEXT NOT NULL, raw_value TEXT NOT NULL, norm_value TEXT NOT NULL, body_path TEXT, source TEXT NOT NULL, confidence TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL, observed_at TEXT NOT NULL, FOREIGN KEY(input_id) REFERENCES inputs(id) ON DELETE CASCADE, FOREIGN KEY(evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT);
      CREATE TABLE credentials (id TEXT PRIMARY KEY, service_id TEXT NOT NULL, endpoint_id TEXT, username TEXT NOT NULL, secret TEXT NOT NULL, secret_type TEXT NOT NULL, source TEXT NOT NULL, confidence TEXT NOT NULL, evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE, FOREIGN KEY(evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT);
      CREATE TABLE vulnerabilities (id TEXT PRIMARY KEY, service_id TEXT NOT NULL, endpoint_id TEXT, vuln_type TEXT NOT NULL, title TEXT NOT NULL, description TEXT, severity TEXT NOT NULL, confidence TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'unverified', evidence_artifact_id TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE, FOREIGN KEY(evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT);
      CREATE TABLE cves (id TEXT PRIMARY KEY, vulnerability_id TEXT NOT NULL, cve_id TEXT NOT NULL, description TEXT, cvss_score REAL, cvss_vector TEXT, reference_url TEXT, created_at TEXT NOT NULL, FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE);
      CREATE TABLE datalog_rules (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT, rule_text TEXT NOT NULL, generated_by TEXT NOT NULL, is_preset INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
      CREATE TABLE technique_docs (id TEXT PRIMARY KEY, source TEXT NOT NULL, file_path TEXT NOT NULL, title TEXT NOT NULL, category TEXT NOT NULL, content TEXT NOT NULL, chunk_index INTEGER NOT NULL, indexed_at TEXT NOT NULL);
      CREATE VIRTUAL TABLE technique_docs_fts USING fts5(title, category, content, content=technique_docs, content_rowid=rowid, tokenize='porter unicode61');
    `);
    db.pragma('user_version = 3');

    // テストデータ挿入
    const ts = now();
    const artifactId = uuid();
    db.prepare(
      `INSERT INTO artifacts (id, tool, kind, path, captured_at) VALUES (?, 'nmap', 'tool_output', '/tmp/scan.xml', ?)`,
    ).run(artifactId, ts);

    const hostId = uuid();
    db.prepare(
      `INSERT INTO hosts (id, authority_kind, authority, created_at, updated_at) VALUES (?, 'IP', '10.0.0.1', ?, ?)`,
    ).run(hostId, ts, ts);

    const serviceId = uuid();
    db.prepare(
      `INSERT INTO services (id, host_id, transport, port, app_proto, proto_confidence, state, evidence_artifact_id, created_at, updated_at) VALUES (?, ?, 'tcp', 80, 'http', 'high', 'open', ?, ?, ?)`,
    ).run(serviceId, hostId, artifactId, ts, ts);

    expect(getUserVersion(db)).toBe(3);

    // v4 マイグレーション実行
    migrateDatabase(db);

    expect(getUserVersion(db)).toBe(LATEST_VERSION);

    // nodes テーブルにデータが移行されている
    const tables = tableNames(db);
    expect(tables).toContain('nodes');
    expect(tables).toContain('edges');
    expect(tables).not.toContain('hosts');

    // host ノードの確認
    const hostNode = db.prepare('SELECT * FROM nodes WHERE id = ?').get(hostId) as Record<
      string,
      unknown
    >;
    expect(hostNode).toBeDefined();
    expect(hostNode.kind).toBe('host');

    // service ノードの確認
    const svcNode = db.prepare('SELECT * FROM nodes WHERE id = ?').get(serviceId) as Record<
      string,
      unknown
    >;
    expect(svcNode).toBeDefined();
    expect(svcNode.kind).toBe('service');

    // HOST_SERVICE edge の確認
    const edge = db
      .prepare(
        `SELECT * FROM edges WHERE kind = 'HOST_SERVICE' AND source_id = ? AND target_id = ?`,
      )
      .get(hostId, serviceId) as Record<string, unknown>;
    expect(edge).toBeDefined();
  });
});
