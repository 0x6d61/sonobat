/**
 * sonobat — Datalog fact extractor
 *
 * Extracts Fact[] from the SQLite database for use by the Datalog evaluator.
 * Each database table maps to one or more fact predicates.
 */

import type Database from 'better-sqlite3';
import type { Fact } from './types.js';

// ---------------------------------------------------------------------------
// Row types for direct SQL queries
// ---------------------------------------------------------------------------

interface HostRow {
  id: string;
  authority: string;
  authority_kind: string;
}

interface ServiceRow {
  host_id: string;
  id: string;
  transport: string;
  port: number;
  app_proto: string;
  state: string;
}

interface HttpEndpointRow {
  service_id: string;
  id: string;
  method: string;
  path: string;
  status_code: number | null;
}

interface InputRow {
  service_id: string;
  id: string;
  location: string;
  name: string;
}

interface EndpointInputRow {
  endpoint_id: string;
  input_id: string;
}

interface ObservationRow {
  input_id: string;
  id: string;
  raw_value: string;
  source: string;
  confidence: string;
}

interface CredentialRow {
  service_id: string;
  id: string;
  username: string;
  secret_type: string;
  source: string;
  confidence: string;
}

interface VulnerabilityRow {
  service_id: string;
  id: string;
  vuln_type: string;
  title: string;
  severity: string;
  confidence: string;
  endpoint_id: string | null;
}

interface CveRow {
  vulnerability_id: string;
  cve_id: string;
  cvss_score: number | null;
}

interface VhostRow {
  host_id: string;
  id: string;
  hostname: string;
  source: string | null;
}

// ---------------------------------------------------------------------------
// Predicate extraction functions
// ---------------------------------------------------------------------------

type ExtractorFn = (db: Database.Database, limit?: number) => Fact[];

function extractHosts(db: Database.Database, limit?: number): Fact[] {
  const sql = limit !== undefined
    ? 'SELECT id, authority, authority_kind FROM hosts LIMIT ?'
    : 'SELECT id, authority, authority_kind FROM hosts';
  const rows = limit !== undefined
    ? db.prepare<[number], HostRow>(sql).all(limit)
    : db.prepare<[], HostRow>(sql).all();
  return rows.map((r) => ({
    predicate: 'host',
    values: [r.id, r.authority, r.authority_kind],
  }));
}

function extractServices(db: Database.Database, limit?: number): Fact[] {
  const sql = limit !== undefined
    ? 'SELECT host_id, id, transport, port, app_proto, state FROM services LIMIT ?'
    : 'SELECT host_id, id, transport, port, app_proto, state FROM services';
  const rows = limit !== undefined
    ? db.prepare<[number], ServiceRow>(sql).all(limit)
    : db.prepare<[], ServiceRow>(sql).all();
  return rows.map((r) => ({
    predicate: 'service',
    values: [r.host_id, r.id, r.transport, r.port, r.app_proto, r.state],
  }));
}

function extractHttpEndpoints(db: Database.Database, limit?: number): Fact[] {
  const sql = limit !== undefined
    ? 'SELECT service_id, id, method, path, status_code FROM http_endpoints LIMIT ?'
    : 'SELECT service_id, id, method, path, status_code FROM http_endpoints';
  const rows = limit !== undefined
    ? db.prepare<[number], HttpEndpointRow>(sql).all(limit)
    : db.prepare<[], HttpEndpointRow>(sql).all();
  return rows.map((r) => ({
    predicate: 'http_endpoint',
    values: [r.service_id, r.id, r.method, r.path, r.status_code ?? 0],
  }));
}

function extractInputs(db: Database.Database, limit?: number): Fact[] {
  const sql = limit !== undefined
    ? 'SELECT service_id, id, location, name FROM inputs LIMIT ?'
    : 'SELECT service_id, id, location, name FROM inputs';
  const rows = limit !== undefined
    ? db.prepare<[number], InputRow>(sql).all(limit)
    : db.prepare<[], InputRow>(sql).all();
  return rows.map((r) => ({
    predicate: 'input',
    values: [r.service_id, r.id, r.location, r.name],
  }));
}

function extractEndpointInputs(db: Database.Database, limit?: number): Fact[] {
  const sql = limit !== undefined
    ? 'SELECT endpoint_id, input_id FROM endpoint_inputs LIMIT ?'
    : 'SELECT endpoint_id, input_id FROM endpoint_inputs';
  const rows = limit !== undefined
    ? db.prepare<[number], EndpointInputRow>(sql).all(limit)
    : db.prepare<[], EndpointInputRow>(sql).all();
  return rows.map((r) => ({
    predicate: 'endpoint_input',
    values: [r.endpoint_id, r.input_id],
  }));
}

function extractObservations(db: Database.Database, limit?: number): Fact[] {
  const sql = limit !== undefined
    ? 'SELECT input_id, id, raw_value, source, confidence FROM observations LIMIT ?'
    : 'SELECT input_id, id, raw_value, source, confidence FROM observations';
  const rows = limit !== undefined
    ? db.prepare<[number], ObservationRow>(sql).all(limit)
    : db.prepare<[], ObservationRow>(sql).all();
  return rows.map((r) => ({
    predicate: 'observation',
    values: [r.input_id, r.id, r.raw_value, r.source, r.confidence],
  }));
}

function extractCredentials(db: Database.Database, limit?: number): Fact[] {
  const sql = limit !== undefined
    ? 'SELECT service_id, id, username, secret_type, source, confidence FROM credentials LIMIT ?'
    : 'SELECT service_id, id, username, secret_type, source, confidence FROM credentials';
  const rows = limit !== undefined
    ? db.prepare<[number], CredentialRow>(sql).all(limit)
    : db.prepare<[], CredentialRow>(sql).all();
  return rows.map((r) => ({
    predicate: 'credential',
    values: [r.service_id, r.id, r.username, r.secret_type, r.source, r.confidence],
  }));
}

function extractVulnerabilities(db: Database.Database, limit?: number): Fact[] {
  const sql = limit !== undefined
    ? 'SELECT service_id, id, vuln_type, title, severity, confidence, endpoint_id FROM vulnerabilities LIMIT ?'
    : 'SELECT service_id, id, vuln_type, title, severity, confidence, endpoint_id FROM vulnerabilities';
  const rows = limit !== undefined
    ? db.prepare<[number], VulnerabilityRow>(sql).all(limit)
    : db.prepare<[], VulnerabilityRow>(sql).all();

  const facts: Fact[] = [];
  for (const r of rows) {
    facts.push({
      predicate: 'vulnerability',
      values: [r.service_id, r.id, r.vuln_type, r.title, r.severity, r.confidence],
    });
  }
  return facts;
}

function extractVulnerabilityEndpoints(db: Database.Database, limit?: number): Fact[] {
  const sql = limit !== undefined
    ? 'SELECT id, endpoint_id FROM vulnerabilities WHERE endpoint_id IS NOT NULL LIMIT ?'
    : 'SELECT id, endpoint_id FROM vulnerabilities WHERE endpoint_id IS NOT NULL';
  const rows = limit !== undefined
    ? db.prepare<[number], { id: string; endpoint_id: string }>(sql).all(limit)
    : db.prepare<[], { id: string; endpoint_id: string }>(sql).all();
  return rows.map((r) => ({
    predicate: 'vulnerability_endpoint',
    values: [r.id, r.endpoint_id],
  }));
}

function extractCves(db: Database.Database, limit?: number): Fact[] {
  const sql = limit !== undefined
    ? 'SELECT vulnerability_id, cve_id, cvss_score FROM cves LIMIT ?'
    : 'SELECT vulnerability_id, cve_id, cvss_score FROM cves';
  const rows = limit !== undefined
    ? db.prepare<[number], CveRow>(sql).all(limit)
    : db.prepare<[], CveRow>(sql).all();
  return rows.map((r) => ({
    predicate: 'cve',
    values: [r.vulnerability_id, r.cve_id, r.cvss_score ?? 0],
  }));
}

function extractVhosts(db: Database.Database, limit?: number): Fact[] {
  const sql = limit !== undefined
    ? 'SELECT host_id, id, hostname, source FROM vhosts LIMIT ?'
    : 'SELECT host_id, id, hostname, source FROM vhosts';
  const rows = limit !== undefined
    ? db.prepare<[number], VhostRow>(sql).all(limit)
    : db.prepare<[], VhostRow>(sql).all();
  return rows.map((r) => ({
    predicate: 'vhost',
    values: [r.host_id, r.id, r.hostname, r.source ?? ''],
  }));
}

// ---------------------------------------------------------------------------
// Predicate → extractor mapping
// ---------------------------------------------------------------------------

const EXTRACTORS: ReadonlyMap<string, ExtractorFn> = new Map<string, ExtractorFn>([
  ['host', extractHosts],
  ['service', extractServices],
  ['http_endpoint', extractHttpEndpoints],
  ['input', extractInputs],
  ['endpoint_input', extractEndpointInputs],
  ['observation', extractObservations],
  ['credential', extractCredentials],
  ['vulnerability', extractVulnerabilities],
  ['vulnerability_endpoint', extractVulnerabilityEndpoints],
  ['cve', extractCves],
  ['vhost', extractVhosts],
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Extract all facts from the SQLite database.
 *
 * Iterates over every supported predicate and extracts facts
 * from the corresponding tables.
 */
export function extractFacts(db: Database.Database): Fact[] {
  const facts: Fact[] = [];
  for (const extractor of EXTRACTORS.values()) {
    facts.push(...extractor(db));
  }
  return facts;
}

/**
 * Extract facts for a specific predicate only.
 *
 * Used by the `list_facts` MCP tool to retrieve facts
 * for a single predicate with optional limit.
 *
 * @param db - SQLite database instance
 * @param predicate - The fact predicate name (e.g. 'host', 'service')
 * @param limit - Optional maximum number of facts to return
 * @returns Array of facts matching the predicate
 */
export function extractFactsByPredicate(
  db: Database.Database,
  predicate: string,
  limit?: number,
): Fact[] {
  const extractor = EXTRACTORS.get(predicate);
  if (!extractor) {
    return [];
  }
  return extractor(db, limit);
}
