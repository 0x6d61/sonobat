import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { Observation } from '../../types/entities.js';
import type { CreateObservationInput } from '../../types/repository.js';

/**
 * Raw row shape returned by better-sqlite3 for the `observations` table.
 * Column names are snake_case as defined in the schema.
 */
interface ObservationRow {
  id: string;
  input_id: string;
  raw_value: string;
  norm_value: string;
  body_path: string | null;
  source: string;
  confidence: string;
  evidence_artifact_id: string;
  observed_at: string;
}

/** Maps a snake_case DB row to a camelCase Observation entity. */
function rowToObservation(row: ObservationRow): Observation {
  return {
    id: row.id,
    inputId: row.input_id,
    rawValue: row.raw_value,
    normValue: row.norm_value,
    bodyPath: row.body_path ?? undefined,
    source: row.source,
    confidence: row.confidence,
    evidenceArtifactId: row.evidence_artifact_id,
    observedAt: row.observed_at,
  };
}

/**
 * Repository for the `observations` table.
 *
 * All queries use prepared statements to prevent SQL injection.
 */
export class ObservationRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /** Insert a new Observation and return the full entity. */
  create(input: CreateObservationInput): Observation {
    const id = crypto.randomUUID();

    const stmt = this.db.prepare<
      [string, string, string, string, string | null, string, string, string, string]
    >(
      `INSERT INTO observations (id, input_id, raw_value, norm_value, body_path, source, confidence, evidence_artifact_id, observed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    stmt.run(
      id,
      input.inputId,
      input.rawValue,
      input.normValue,
      input.bodyPath ?? null,
      input.source,
      input.confidence,
      input.evidenceArtifactId,
      input.observedAt,
    );

    return {
      id,
      inputId: input.inputId,
      rawValue: input.rawValue,
      normValue: input.normValue,
      bodyPath: input.bodyPath,
      source: input.source,
      confidence: input.confidence,
      evidenceArtifactId: input.evidenceArtifactId,
      observedAt: input.observedAt,
    };
  }

  /** Find an Observation by its primary key. Returns undefined if not found. */
  findById(id: string): Observation | undefined {
    const stmt = this.db.prepare<[string], ObservationRow>(
      `SELECT id, input_id, raw_value, norm_value, body_path, source, confidence, evidence_artifact_id, observed_at
       FROM observations
       WHERE id = ?`,
    );

    const row = stmt.get(id);
    return row ? rowToObservation(row) : undefined;
  }

  /** Return all Observations for a given input ID. */
  findByInputId(inputId: string): Observation[] {
    const stmt = this.db.prepare<[string], ObservationRow>(
      `SELECT id, input_id, raw_value, norm_value, body_path, source, confidence, evidence_artifact_id, observed_at
       FROM observations
       WHERE input_id = ?`,
    );

    const rows = stmt.all(inputId);
    return rows.map(rowToObservation);
  }

  /** Delete an Observation by id. Returns true if a row was deleted. */
  delete(id: string): boolean {
    const stmt = this.db.prepare<[string]>('DELETE FROM observations WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }
}
