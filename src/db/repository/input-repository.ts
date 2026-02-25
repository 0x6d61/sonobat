import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { Input } from '../../types/entities.js';
import type { CreateInputInput, UpdateInputInput } from '../../types/repository.js';

/**
 * Raw row shape returned by better-sqlite3 for the `inputs` table.
 * Column names are snake_case as defined in the schema.
 */
interface InputRow {
  id: string;
  service_id: string;
  location: string;
  name: string;
  type_hint: string | null;
  created_at: string;
  updated_at: string;
}

/** Maps a snake_case DB row to a camelCase Input entity. */
function rowToInput(row: InputRow): Input {
  return {
    id: row.id,
    serviceId: row.service_id,
    location: row.location,
    name: row.name,
    typeHint: row.type_hint ?? undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Repository for the `inputs` table.
 *
 * All queries use prepared statements to prevent SQL injection.
 */
export class InputRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /** Insert a new Input and return the full entity. */
  create(input: CreateInputInput): Input {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const stmt = this.db.prepare<
      [string, string, string, string, string | null, string, string]
    >(
      `INSERT INTO inputs (id, service_id, location, name, type_hint, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );

    stmt.run(
      id,
      input.serviceId,
      input.location,
      input.name,
      input.typeHint ?? null,
      now,
      now,
    );

    return {
      id,
      serviceId: input.serviceId,
      location: input.location,
      name: input.name,
      typeHint: input.typeHint,
      createdAt: now,
      updatedAt: now,
    };
  }

  /** Find an Input by its primary key. Returns undefined if not found. */
  findById(id: string): Input | undefined {
    const stmt = this.db.prepare<[string], InputRow>(
      `SELECT id, service_id, location, name, type_hint, created_at, updated_at
       FROM inputs
       WHERE id = ?`,
    );

    const row = stmt.get(id);
    return row ? rowToInput(row) : undefined;
  }

  /**
   * Find all Inputs for a given service.
   * If location is provided, further filter by location.
   */
  findByServiceId(serviceId: string, location?: string): Input[] {
    if (location !== undefined) {
      const stmt = this.db.prepare<[string, string], InputRow>(
        `SELECT id, service_id, location, name, type_hint, created_at, updated_at
         FROM inputs
         WHERE service_id = ? AND location = ?`,
      );

      const rows = stmt.all(serviceId, location);
      return rows.map(rowToInput);
    }

    const stmt = this.db.prepare<[string], InputRow>(
      `SELECT id, service_id, location, name, type_hint, created_at, updated_at
       FROM inputs
       WHERE service_id = ?`,
    );

    const rows = stmt.all(serviceId);
    return rows.map(rowToInput);
  }

  /**
   * Update an existing Input with the provided fields.
   * Always bumps `updated_at`. Returns the updated entity, or undefined if
   * the Input was not found.
   */
  update(id: string, input: UpdateInputInput): Input | undefined {
    const setClauses: string[] = [];
    const params: unknown[] = [];

    if (input.typeHint !== undefined) {
      setClauses.push('type_hint = ?');
      params.push(input.typeHint);
    }

    const now = new Date().toISOString();
    setClauses.push('updated_at = ?');
    params.push(now);

    // Always include the WHERE id
    params.push(id);

    const sql = `UPDATE inputs SET ${setClauses.join(', ')} WHERE id = ?`;
    const stmt = this.db.prepare(sql);
    const result = stmt.run(...params);

    if (result.changes === 0) {
      return undefined;
    }

    return this.findById(id);
  }

  /** Delete an Input by id. Returns true if a row was deleted. */
  delete(id: string): boolean {
    const stmt = this.db.prepare<[string]>('DELETE FROM inputs WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }
}
