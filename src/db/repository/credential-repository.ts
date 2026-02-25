import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { Credential } from '../../types/entities.js';
import type { CreateCredentialInput } from '../../types/repository.js';

/**
 * Raw row shape returned by better-sqlite3 for the `credentials` table.
 * Column names are snake_case as defined in the schema.
 */
interface CredentialRow {
  id: string;
  service_id: string;
  endpoint_id: string | null;
  username: string;
  secret: string;
  secret_type: string;
  source: string;
  confidence: string;
  evidence_artifact_id: string;
  created_at: string;
}

/** Maps a snake_case DB row to a camelCase Credential entity. */
function rowToCredential(row: CredentialRow): Credential {
  return {
    id: row.id,
    serviceId: row.service_id,
    endpointId: row.endpoint_id ?? undefined,
    username: row.username,
    secret: row.secret,
    secretType: row.secret_type,
    source: row.source,
    confidence: row.confidence,
    evidenceArtifactId: row.evidence_artifact_id,
    createdAt: row.created_at,
  };
}

/**
 * Repository for the `credentials` table.
 *
 * All queries use prepared statements to prevent SQL injection.
 */
export class CredentialRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /** Insert a new Credential and return the full entity. */
  create(input: CreateCredentialInput): Credential {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const stmt = this.db.prepare<
      [string, string, string | null, string, string, string, string, string, string, string]
    >(
      `INSERT INTO credentials (id, service_id, endpoint_id, username, secret, secret_type, source, confidence, evidence_artifact_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    stmt.run(
      id,
      input.serviceId,
      input.endpointId ?? null,
      input.username,
      input.secret,
      input.secretType,
      input.source,
      input.confidence,
      input.evidenceArtifactId,
      now,
    );

    return {
      id,
      serviceId: input.serviceId,
      endpointId: input.endpointId ?? undefined,
      username: input.username,
      secret: input.secret,
      secretType: input.secretType,
      source: input.source,
      confidence: input.confidence,
      evidenceArtifactId: input.evidenceArtifactId,
      createdAt: now,
    };
  }

  /** Find a Credential by its primary key. Returns undefined if not found. */
  findById(id: string): Credential | undefined {
    const stmt = this.db.prepare<[string], CredentialRow>(
      `SELECT id, service_id, endpoint_id, username, secret, secret_type, source, confidence, evidence_artifact_id, created_at
       FROM credentials
       WHERE id = ?`,
    );

    const row = stmt.get(id);
    return row ? rowToCredential(row) : undefined;
  }

  /** Return all Credentials for a given service. */
  findByServiceId(serviceId: string): Credential[] {
    const stmt = this.db.prepare<[string], CredentialRow>(
      `SELECT id, service_id, endpoint_id, username, secret, secret_type, source, confidence, evidence_artifact_id, created_at
       FROM credentials
       WHERE service_id = ?`,
    );

    const rows = stmt.all(serviceId);
    return rows.map(rowToCredential);
  }

  /** Return all Credentials across all services. */
  findAll(): Credential[] {
    const stmt = this.db.prepare<[], CredentialRow>(
      `SELECT id, service_id, endpoint_id, username, secret, secret_type, source, confidence, evidence_artifact_id, created_at
       FROM credentials`,
    );

    const rows = stmt.all();
    return rows.map(rowToCredential);
  }

  /** Delete a Credential by id. Returns true if a row was deleted. */
  delete(id: string): boolean {
    const stmt = this.db.prepare<[string]>('DELETE FROM credentials WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }
}
