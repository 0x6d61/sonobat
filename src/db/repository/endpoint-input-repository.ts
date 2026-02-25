import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { EndpointInput } from '../../types/entities.js';
import type { CreateEndpointInputInput } from '../../types/repository.js';

/**
 * Raw row shape returned by better-sqlite3 for the `endpoint_inputs` table.
 * Column names are snake_case as defined in the schema.
 */
interface EndpointInputRow {
  id: string;
  endpoint_id: string;
  input_id: string;
  evidence_artifact_id: string;
  created_at: string;
}

/** Maps a snake_case DB row to a camelCase EndpointInput entity. */
function rowToEndpointInput(row: EndpointInputRow): EndpointInput {
  return {
    id: row.id,
    endpointId: row.endpoint_id,
    inputId: row.input_id,
    evidenceArtifactId: row.evidence_artifact_id,
    createdAt: row.created_at,
  };
}

/**
 * Repository for the `endpoint_inputs` table.
 *
 * All queries use prepared statements to prevent SQL injection.
 */
export class EndpointInputRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /** Insert a new EndpointInput and return the full entity. */
  create(input: CreateEndpointInputInput): EndpointInput {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const stmt = this.db.prepare<
      [string, string, string, string, string]
    >(
      `INSERT INTO endpoint_inputs (id, endpoint_id, input_id, evidence_artifact_id, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    );

    stmt.run(
      id,
      input.endpointId,
      input.inputId,
      input.evidenceArtifactId,
      now,
    );

    return {
      id,
      endpointId: input.endpointId,
      inputId: input.inputId,
      evidenceArtifactId: input.evidenceArtifactId,
      createdAt: now,
    };
  }

  /** Find an EndpointInput by its primary key. Returns undefined if not found. */
  findById(id: string): EndpointInput | undefined {
    const stmt = this.db.prepare<[string], EndpointInputRow>(
      `SELECT id, endpoint_id, input_id, evidence_artifact_id, created_at
       FROM endpoint_inputs
       WHERE id = ?`,
    );

    const row = stmt.get(id);
    return row ? rowToEndpointInput(row) : undefined;
  }

  /** Find all EndpointInputs for a given endpoint. */
  findByEndpointId(endpointId: string): EndpointInput[] {
    const stmt = this.db.prepare<[string], EndpointInputRow>(
      `SELECT id, endpoint_id, input_id, evidence_artifact_id, created_at
       FROM endpoint_inputs
       WHERE endpoint_id = ?`,
    );

    const rows = stmt.all(endpointId);
    return rows.map(rowToEndpointInput);
  }

  /** Find all EndpointInputs for a given input. */
  findByInputId(inputId: string): EndpointInput[] {
    const stmt = this.db.prepare<[string], EndpointInputRow>(
      `SELECT id, endpoint_id, input_id, evidence_artifact_id, created_at
       FROM endpoint_inputs
       WHERE input_id = ?`,
    );

    const rows = stmt.all(inputId);
    return rows.map(rowToEndpointInput);
  }

  /** Delete an EndpointInput by id. Returns true if a row was deleted. */
  delete(id: string): boolean {
    const stmt = this.db.prepare<[string]>('DELETE FROM endpoint_inputs WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }
}
