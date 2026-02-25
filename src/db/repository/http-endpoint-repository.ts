import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { HttpEndpoint } from '../../types/entities.js';
import type { CreateHttpEndpointInput } from '../../types/repository.js';

/**
 * Raw row shape returned by better-sqlite3 for the `http_endpoints` table.
 * Column names are snake_case as defined in the schema.
 */
interface HttpEndpointRow {
  id: string;
  service_id: string;
  vhost_id: string | null;
  base_uri: string;
  method: string;
  path: string;
  status_code: number | null;
  content_length: number | null;
  words: number | null;
  lines: number | null;
  evidence_artifact_id: string;
  created_at: string;
}

/** Maps a snake_case DB row to a camelCase HttpEndpoint entity. */
function rowToHttpEndpoint(row: HttpEndpointRow): HttpEndpoint {
  return {
    id: row.id,
    serviceId: row.service_id,
    vhostId: row.vhost_id ?? undefined,
    baseUri: row.base_uri,
    method: row.method,
    path: row.path,
    statusCode: row.status_code ?? undefined,
    contentLength: row.content_length ?? undefined,
    words: row.words ?? undefined,
    lines: row.lines ?? undefined,
    evidenceArtifactId: row.evidence_artifact_id,
    createdAt: row.created_at,
  };
}

/**
 * Repository for the `http_endpoints` table.
 *
 * All queries use prepared statements to prevent SQL injection.
 */
export class HttpEndpointRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /** Insert a new HttpEndpoint and return the full entity. */
  create(input: CreateHttpEndpointInput): HttpEndpoint {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const stmt = this.db.prepare(
      `INSERT INTO http_endpoints (id, service_id, vhost_id, base_uri, method, path, status_code, content_length, words, lines, evidence_artifact_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    stmt.run(
      id,
      input.serviceId,
      input.vhostId ?? null,
      input.baseUri,
      input.method,
      input.path,
      input.statusCode ?? null,
      input.contentLength ?? null,
      input.words ?? null,
      input.lines ?? null,
      input.evidenceArtifactId,
      now,
    );

    return {
      id,
      serviceId: input.serviceId,
      vhostId: input.vhostId,
      baseUri: input.baseUri,
      method: input.method,
      path: input.path,
      statusCode: input.statusCode,
      contentLength: input.contentLength,
      words: input.words,
      lines: input.lines,
      evidenceArtifactId: input.evidenceArtifactId,
      createdAt: now,
    };
  }

  /** Find an HttpEndpoint by its primary key. Returns undefined if not found. */
  findById(id: string): HttpEndpoint | undefined {
    const stmt = this.db.prepare<[string], HttpEndpointRow>(
      `SELECT id, service_id, vhost_id, base_uri, method, path, status_code, content_length, words, lines, evidence_artifact_id, created_at
       FROM http_endpoints
       WHERE id = ?`,
    );

    const row = stmt.get(id);
    return row ? rowToHttpEndpoint(row) : undefined;
  }

  /** Return all HttpEndpoints for a given service. */
  findByServiceId(serviceId: string): HttpEndpoint[] {
    const stmt = this.db.prepare<[string], HttpEndpointRow>(
      `SELECT id, service_id, vhost_id, base_uri, method, path, status_code, content_length, words, lines, evidence_artifact_id, created_at
       FROM http_endpoints
       WHERE service_id = ?`,
    );

    const rows = stmt.all(serviceId);
    return rows.map(rowToHttpEndpoint);
  }

  /** Delete an HttpEndpoint by id. Returns true if a row was deleted. */
  delete(id: string): boolean {
    const stmt = this.db.prepare<[string]>(
      'DELETE FROM http_endpoints WHERE id = ?',
    );
    const result = stmt.run(id);
    return result.changes > 0;
  }
}
