/**
 * sonobat — AttackDataGraph SQLite schema
 *
 * This schema is the single source of truth for the database structure.
 * It is derived from docs/architecture.md Section 4.
 */

export const SCHEMA_SQL = `
PRAGMA foreign_keys = ON;

-- ============================================================
-- 実行単位（任意）
-- ============================================================
CREATE TABLE IF NOT EXISTS scans (
  id            TEXT PRIMARY KEY,
  started_at    TEXT NOT NULL,
  finished_at   TEXT,
  notes         TEXT
);

-- ============================================================
-- 生出力（ファイル）参照
-- ============================================================
CREATE TABLE IF NOT EXISTS artifacts (
  id            TEXT PRIMARY KEY,
  scan_id       TEXT,
  tool          TEXT NOT NULL,              -- "nmap" | "ffuf" | "nuclei"
  kind          TEXT NOT NULL,              -- "tool_output" | "http_request" | "http_response"
  path          TEXT NOT NULL,              -- ローカルファイルパス or URI
  sha256        TEXT,
  captured_at   TEXT NOT NULL,
  attrs_json    TEXT,                       -- 任意メタ（コマンド、引数等）
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_tool ON artifacts(tool);

-- ============================================================
-- ホスト
-- ============================================================
CREATE TABLE IF NOT EXISTS hosts (
  id                TEXT PRIMARY KEY,
  authority_kind    TEXT NOT NULL,           -- "IP" | "DOMAIN"
  authority         TEXT NOT NULL UNIQUE,    -- IP アドレスまたはドメイン名
  resolved_ips_json TEXT NOT NULL DEFAULT '[]',
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

-- ============================================================
-- バーチャルホスト
-- ============================================================
CREATE TABLE IF NOT EXISTS vhosts (
  id                    TEXT PRIMARY KEY,
  host_id               TEXT NOT NULL,
  hostname              TEXT NOT NULL,
  source                TEXT,               -- "nmap" | "cert" | "header" | "manual"
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  UNIQUE (host_id, hostname),
  FOREIGN KEY (host_id)              REFERENCES hosts(id)     ON DELETE CASCADE,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_vhosts_host ON vhosts(host_id);

-- ============================================================
-- サービス
-- ============================================================
CREATE TABLE IF NOT EXISTS services (
  id                    TEXT PRIMARY KEY,
  host_id               TEXT NOT NULL,
  transport             TEXT NOT NULL,       -- "tcp" | "udp"
  port                  INTEGER NOT NULL,
  app_proto             TEXT NOT NULL,       -- "http" | "ssh" | "ftp" 等
  proto_confidence      TEXT NOT NULL,       -- "high" | "medium" | "low"
  banner                TEXT,
  product               TEXT,
  version               TEXT,
  state                 TEXT NOT NULL,       -- "open" | "closed" | "filtered"
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL,
  UNIQUE (host_id, transport, port),
  FOREIGN KEY (host_id)              REFERENCES hosts(id)     ON DELETE CASCADE,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);

-- ============================================================
-- サービス観測（key-value）
-- ============================================================
CREATE TABLE IF NOT EXISTS service_observations (
  id                    TEXT PRIMARY KEY,
  service_id            TEXT NOT NULL,
  key                   TEXT NOT NULL,
  value                 TEXT NOT NULL,
  confidence            TEXT NOT NULL,       -- "high" | "medium" | "low"
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  FOREIGN KEY (service_id)           REFERENCES services(id)  ON DELETE CASCADE,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_svc_obs_service ON service_observations(service_id);

-- ============================================================
-- HTTP エンドポイント
-- ============================================================
CREATE TABLE IF NOT EXISTS http_endpoints (
  id                    TEXT PRIMARY KEY,
  service_id            TEXT NOT NULL,
  vhost_id              TEXT,
  base_uri              TEXT NOT NULL,       -- "http://example.com:80"
  method                TEXT NOT NULL,       -- "GET" | "POST" | ...
  path                  TEXT NOT NULL,       -- "/admin"（クエリは含めない）
  status_code           INTEGER,
  content_length        INTEGER,
  words                 INTEGER,
  lines                 INTEGER,
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  UNIQUE (service_id, method, path),
  FOREIGN KEY (service_id)           REFERENCES services(id)  ON DELETE CASCADE,
  FOREIGN KEY (vhost_id)             REFERENCES vhosts(id)    ON DELETE SET NULL,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_endpoints_service ON http_endpoints(service_id);

-- ============================================================
-- 入力パラメータ
-- ============================================================
CREATE TABLE IF NOT EXISTS inputs (
  id            TEXT PRIMARY KEY,
  service_id    TEXT NOT NULL,
  location      TEXT NOT NULL,              -- "query" | "path" | "body" | "header" | "cookie"
  name          TEXT NOT NULL,
  type_hint     TEXT,                       -- "string" | "int" | "json" 等（任意）
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  UNIQUE (service_id, location, name),
  FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_inputs_service ON inputs(service_id);

-- ============================================================
-- エンドポイント ↔ 入力（多対多）
-- ============================================================
CREATE TABLE IF NOT EXISTS endpoint_inputs (
  id                    TEXT PRIMARY KEY,
  endpoint_id           TEXT NOT NULL,
  input_id              TEXT NOT NULL,
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  UNIQUE (endpoint_id, input_id),
  FOREIGN KEY (endpoint_id)          REFERENCES http_endpoints(id) ON DELETE CASCADE,
  FOREIGN KEY (input_id)             REFERENCES inputs(id)         ON DELETE CASCADE,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id)      ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_ep_inputs_endpoint ON endpoint_inputs(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_ep_inputs_input    ON endpoint_inputs(input_id);

-- ============================================================
-- 観測値
-- ============================================================
CREATE TABLE IF NOT EXISTS observations (
  id                    TEXT PRIMARY KEY,
  input_id              TEXT NOT NULL,
  raw_value             TEXT NOT NULL,
  norm_value            TEXT NOT NULL,
  body_path             TEXT,               -- JSON Pointer 等（例: "/user/name"）
  source                TEXT NOT NULL,       -- "ffuf_url" | "req_query" | "req_body" | "manual"
  confidence            TEXT NOT NULL,       -- "high" | "medium" | "low"
  evidence_artifact_id  TEXT NOT NULL,
  observed_at           TEXT NOT NULL,
  FOREIGN KEY (input_id)             REFERENCES inputs(id)    ON DELETE CASCADE,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_obs_input ON observations(input_id);

-- ============================================================
-- 認証情報
-- ============================================================
CREATE TABLE IF NOT EXISTS credentials (
  id                    TEXT PRIMARY KEY,
  service_id            TEXT NOT NULL,
  endpoint_id           TEXT,               -- HTTP の場合のみ（任意）
  username              TEXT NOT NULL,
  secret                TEXT NOT NULL,
  secret_type           TEXT NOT NULL,       -- "password" | "token" | "api_key" | "ssh_key"
  source                TEXT NOT NULL,       -- "brute_force" | "default" | "leaked" | "manual"
  confidence            TEXT NOT NULL,       -- "high" | "medium" | "low"
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  FOREIGN KEY (service_id)           REFERENCES services(id)       ON DELETE CASCADE,
  FOREIGN KEY (endpoint_id)          REFERENCES http_endpoints(id) ON DELETE SET NULL,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id)      ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_creds_service  ON credentials(service_id);
CREATE INDEX IF NOT EXISTS idx_creds_endpoint ON credentials(endpoint_id);

-- ============================================================
-- 脆弱性
-- ============================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id                    TEXT PRIMARY KEY,
  service_id            TEXT NOT NULL,
  endpoint_id           TEXT,               -- HTTP の場合のみ（任意）
  vuln_type             TEXT NOT NULL,       -- "sqli" | "xss" | "rce" | "lfi" | "ssrf" | ...
  title                 TEXT NOT NULL,
  description           TEXT,
  severity              TEXT NOT NULL,       -- "critical" | "high" | "medium" | "low" | "info"
  confidence            TEXT NOT NULL,       -- "high" | "medium" | "low"
  status                TEXT NOT NULL DEFAULT 'unverified', -- "unverified" | "confirmed" | "false_positive" | "not_exploitable"
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  FOREIGN KEY (service_id)           REFERENCES services(id)       ON DELETE CASCADE,
  FOREIGN KEY (endpoint_id)          REFERENCES http_endpoints(id) ON DELETE SET NULL,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id)      ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_vulns_service  ON vulnerabilities(service_id);
CREATE INDEX IF NOT EXISTS idx_vulns_endpoint ON vulnerabilities(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);

-- ============================================================
-- CVE 情報
-- ============================================================
CREATE TABLE IF NOT EXISTS cves (
  id                TEXT PRIMARY KEY,
  vulnerability_id  TEXT NOT NULL,
  cve_id            TEXT NOT NULL,          -- "CVE-YYYY-NNNNN"
  description       TEXT,
  cvss_score        REAL,
  cvss_vector       TEXT,
  reference_url     TEXT,
  created_at        TEXT NOT NULL,
  FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cves_vuln ON cves(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_cves_cveid ON cves(cve_id);

-- ============================================================
-- Datalog ルール保存
-- ============================================================
CREATE TABLE IF NOT EXISTS datalog_rules (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  description   TEXT,
  rule_text     TEXT NOT NULL,
  generated_by  TEXT NOT NULL,            -- "human" | "ai" | "preset"
  is_preset     INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_datalog_rules_name ON datalog_rules(name);

-- ============================================================
-- テクニックドキュメント（HackTricks 等の知識ベース）
-- ============================================================
CREATE TABLE IF NOT EXISTS technique_docs (
  id            TEXT PRIMARY KEY,
  source        TEXT NOT NULL,           -- "hacktricks"
  file_path     TEXT NOT NULL,           -- "linux-hardening/privilege-escalation/docker-breakout.md"
  title         TEXT NOT NULL,           -- H1 見出し or ファイル名
  category      TEXT NOT NULL,           -- ディレクトリ構造 "linux-hardening/privilege-escalation"
  content       TEXT NOT NULL,           -- Markdown チャンク本文
  chunk_index   INTEGER NOT NULL,        -- ファイル内のチャンク番号 (0-based)
  indexed_at    TEXT NOT NULL
);

-- FTS5 外部コンテンツテーブル (technique_docs をソースとする)
CREATE VIRTUAL TABLE IF NOT EXISTS technique_docs_fts USING fts5(
  title, category, content,
  content=technique_docs,
  content_rowid=rowid,
  tokenize='porter unicode61'
);

-- 同期トリガー
CREATE TRIGGER IF NOT EXISTS technique_docs_ai AFTER INSERT ON technique_docs BEGIN
  INSERT INTO technique_docs_fts(rowid, title, category, content)
  VALUES (new.rowid, new.title, new.category, new.content);
END;

CREATE TRIGGER IF NOT EXISTS technique_docs_ad AFTER DELETE ON technique_docs BEGIN
  INSERT INTO technique_docs_fts(technique_docs_fts, rowid, title, category, content)
  VALUES ('delete', old.rowid, old.title, old.category, old.content);
END;

CREATE TRIGGER IF NOT EXISTS technique_docs_au AFTER UPDATE ON technique_docs BEGIN
  INSERT INTO technique_docs_fts(technique_docs_fts, rowid, title, category, content)
  VALUES ('delete', old.rowid, old.title, old.category, old.content);
  INSERT INTO technique_docs_fts(rowid, title, category, content)
  VALUES (new.rowid, new.title, new.category, new.content);
END;
` as const;
