import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { ServiceObservation } from '../../types/entities.js';
import type { CreateServiceObservationInput } from '../../types/repository.js';

/**
 * Raw row shape returned by better-sqlite3 for the `service_observations` table.
 * Column names are snake_case as defined in the schema.
 */
interface ServiceObservationRow {
  id: string;
  service_id: string;
  key: string;
  value: string;
  confidence: string;
  evidence_artifact_id: string;
  created_at: string;
}

/** Maps a snake_case DB row to a camelCase ServiceObservation entity. */
function rowToServiceObservation(row: ServiceObservationRow): ServiceObservation {
  return {
    id: row.id,
    serviceId: row.service_id,
    key: row.key,
    value: row.value,
    confidence: row.confidence,
    evidenceArtifactId: row.evidence_artifact_id,
    createdAt: row.created_at,
  };
}

/**
 * Repository for the `service_observations` table.
 *
 * All queries use prepared statements to prevent SQL injection.
 */
export class ServiceObservationRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /** Insert a new ServiceObservation and return the full entity. */
  create(input: CreateServiceObservationInput): ServiceObservation {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const stmt = this.db.prepare<[string, string, string, string, string, string, string]>(
      `INSERT INTO service_observations (id, service_id, key, value, confidence, evidence_artifact_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );

    stmt.run(
      id,
      input.serviceId,
      input.key,
      input.value,
      input.confidence,
      input.evidenceArtifactId,
      now,
    );

    return {
      id,
      serviceId: input.serviceId,
      key: input.key,
      value: input.value,
      confidence: input.confidence,
      evidenceArtifactId: input.evidenceArtifactId,
      createdAt: now,
    };
  }

  /** Find a ServiceObservation by its primary key. Returns undefined if not found. */
  findById(id: string): ServiceObservation | undefined {
    const stmt = this.db.prepare<[string], ServiceObservationRow>(
      `SELECT id, service_id, key, value, confidence, evidence_artifact_id, created_at
       FROM service_observations
       WHERE id = ?`,
    );

    const row = stmt.get(id);
    return row ? rowToServiceObservation(row) : undefined;
  }

  /** Return all ServiceObservations for a given service. */
  findByServiceId(serviceId: string): ServiceObservation[] {
    const stmt = this.db.prepare<[string], ServiceObservationRow>(
      `SELECT id, service_id, key, value, confidence, evidence_artifact_id, created_at
       FROM service_observations
       WHERE service_id = ?`,
    );

    const rows = stmt.all(serviceId);
    return rows.map(rowToServiceObservation);
  }

  /** Delete a ServiceObservation by id. Returns true if a row was deleted. */
  delete(id: string): boolean {
    const stmt = this.db.prepare<[string]>('DELETE FROM service_observations WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }
}
