/**
 * Migration v0: Base schema
 *
 * 元の sonobat スキーマ（v1/v2/v3 の追加分を除く）。
 * fresh DB でマイグレーション順次実行するための基盤。
 */

import type Database from 'better-sqlite3';
import type { Migration } from './index.js';

const migration: Migration = {
  version: 0,
  description: 'Base schema (scans, artifacts, hosts, services, endpoints, etc.)',
  up(db: Database.Database): void {
    db.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        id            TEXT PRIMARY KEY,
        started_at    TEXT NOT NULL,
        finished_at   TEXT,
        notes         TEXT
      );

      CREATE TABLE IF NOT EXISTS artifacts (
        id            TEXT PRIMARY KEY,
        scan_id       TEXT,
        tool          TEXT NOT NULL,
        kind          TEXT NOT NULL,
        path          TEXT NOT NULL,
        sha256        TEXT,
        captured_at   TEXT NOT NULL,
        attrs_json    TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_artifacts_tool ON artifacts(tool);

      CREATE TABLE IF NOT EXISTS hosts (
        id                TEXT PRIMARY KEY,
        authority_kind    TEXT NOT NULL,
        authority         TEXT NOT NULL UNIQUE,
        resolved_ips_json TEXT NOT NULL DEFAULT '[]',
        created_at        TEXT NOT NULL,
        updated_at        TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS vhosts (
        id                    TEXT PRIMARY KEY,
        host_id               TEXT NOT NULL,
        hostname              TEXT NOT NULL,
        source                TEXT,
        evidence_artifact_id  TEXT NOT NULL,
        created_at            TEXT NOT NULL,
        UNIQUE (host_id, hostname),
        FOREIGN KEY (host_id)              REFERENCES hosts(id)     ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_vhosts_host ON vhosts(host_id);

      CREATE TABLE IF NOT EXISTS services (
        id                    TEXT PRIMARY KEY,
        host_id               TEXT NOT NULL,
        transport             TEXT NOT NULL,
        port                  INTEGER NOT NULL,
        app_proto             TEXT NOT NULL,
        proto_confidence      TEXT NOT NULL,
        banner                TEXT,
        product               TEXT,
        version               TEXT,
        state                 TEXT NOT NULL,
        evidence_artifact_id  TEXT NOT NULL,
        created_at            TEXT NOT NULL,
        updated_at            TEXT NOT NULL,
        UNIQUE (host_id, transport, port),
        FOREIGN KEY (host_id)              REFERENCES hosts(id)     ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);

      CREATE TABLE IF NOT EXISTS service_observations (
        id                    TEXT PRIMARY KEY,
        service_id            TEXT NOT NULL,
        key                   TEXT NOT NULL,
        value                 TEXT NOT NULL,
        confidence            TEXT NOT NULL,
        evidence_artifact_id  TEXT NOT NULL,
        created_at            TEXT NOT NULL,
        FOREIGN KEY (service_id)           REFERENCES services(id)  ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_svc_obs_service ON service_observations(service_id);

      CREATE TABLE IF NOT EXISTS http_endpoints (
        id                    TEXT PRIMARY KEY,
        service_id            TEXT NOT NULL,
        vhost_id              TEXT,
        base_uri              TEXT NOT NULL,
        method                TEXT NOT NULL,
        path                  TEXT NOT NULL,
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

      CREATE TABLE IF NOT EXISTS inputs (
        id            TEXT PRIMARY KEY,
        service_id    TEXT NOT NULL,
        location      TEXT NOT NULL,
        name          TEXT NOT NULL,
        type_hint     TEXT,
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL,
        UNIQUE (service_id, location, name),
        FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_inputs_service ON inputs(service_id);

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

      CREATE TABLE IF NOT EXISTS observations (
        id                    TEXT PRIMARY KEY,
        input_id              TEXT NOT NULL,
        raw_value             TEXT NOT NULL,
        norm_value            TEXT NOT NULL,
        body_path             TEXT,
        source                TEXT NOT NULL,
        confidence            TEXT NOT NULL,
        evidence_artifact_id  TEXT NOT NULL,
        observed_at           TEXT NOT NULL,
        FOREIGN KEY (input_id)             REFERENCES inputs(id)    ON DELETE CASCADE,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_obs_input ON observations(input_id);

      CREATE TABLE IF NOT EXISTS credentials (
        id                    TEXT PRIMARY KEY,
        service_id            TEXT NOT NULL,
        endpoint_id           TEXT,
        username              TEXT NOT NULL,
        secret                TEXT NOT NULL,
        secret_type           TEXT NOT NULL,
        source                TEXT NOT NULL,
        confidence            TEXT NOT NULL,
        evidence_artifact_id  TEXT NOT NULL,
        created_at            TEXT NOT NULL,
        FOREIGN KEY (service_id)           REFERENCES services(id)       ON DELETE CASCADE,
        FOREIGN KEY (endpoint_id)          REFERENCES http_endpoints(id) ON DELETE SET NULL,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id)      ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_creds_service  ON credentials(service_id);
      CREATE INDEX IF NOT EXISTS idx_creds_endpoint ON credentials(endpoint_id);

      CREATE TABLE IF NOT EXISTS vulnerabilities (
        id                    TEXT PRIMARY KEY,
        service_id            TEXT NOT NULL,
        endpoint_id           TEXT,
        vuln_type             TEXT NOT NULL,
        title                 TEXT NOT NULL,
        description           TEXT,
        severity              TEXT NOT NULL,
        confidence            TEXT NOT NULL,
        evidence_artifact_id  TEXT NOT NULL,
        created_at            TEXT NOT NULL,
        FOREIGN KEY (service_id)           REFERENCES services(id)       ON DELETE CASCADE,
        FOREIGN KEY (endpoint_id)          REFERENCES http_endpoints(id) ON DELETE SET NULL,
        FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id)      ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_vulns_service  ON vulnerabilities(service_id);
      CREATE INDEX IF NOT EXISTS idx_vulns_endpoint ON vulnerabilities(endpoint_id);
      CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);

      CREATE TABLE IF NOT EXISTS cves (
        id                TEXT PRIMARY KEY,
        vulnerability_id  TEXT NOT NULL,
        cve_id            TEXT NOT NULL,
        description       TEXT,
        cvss_score        REAL,
        cvss_vector       TEXT,
        reference_url     TEXT,
        created_at        TEXT NOT NULL,
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_cves_vuln ON cves(vulnerability_id);
      CREATE INDEX IF NOT EXISTS idx_cves_cveid ON cves(cve_id);
    `);
  },
};

export default migration;
