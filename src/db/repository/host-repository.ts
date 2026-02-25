import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { Host } from '../../types/entities.js';
import type { CreateHostInput, UpdateHostInput } from '../../types/repository.js';

/**
 * Raw row shape returned by better-sqlite3 for the `hosts` table.
 * Column names are snake_case as defined in the schema.
 */
interface HostRow {
  id: string;
  authority_kind: string;
  authority: string;
  resolved_ips_json: string;
  created_at: string;
  updated_at: string;
}

/** Maps a snake_case DB row to a camelCase Host entity. */
function rowToHost(row: HostRow): Host {
  return {
    id: row.id,
    authorityKind: row.authority_kind,
    authority: row.authority,
    resolvedIpsJson: row.resolved_ips_json,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Repository for the `hosts` table.
 *
 * All queries use prepared statements to prevent SQL injection.
 */
export class HostRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /** Insert a new Host and return the full entity. */
  create(input: CreateHostInput): Host {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const stmt = this.db.prepare<
      [string, string, string, string, string, string]
    >(
      `INSERT INTO hosts (id, authority_kind, authority, resolved_ips_json, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    );

    stmt.run(
      id,
      input.authorityKind,
      input.authority,
      input.resolvedIpsJson,
      now,
      now,
    );

    return {
      id,
      authorityKind: input.authorityKind,
      authority: input.authority,
      resolvedIpsJson: input.resolvedIpsJson,
      createdAt: now,
      updatedAt: now,
    };
  }

  /** Find a Host by its primary key. Returns undefined if not found. */
  findById(id: string): Host | undefined {
    const stmt = this.db.prepare<[string], HostRow>(
      `SELECT id, authority_kind, authority, resolved_ips_json, created_at, updated_at
       FROM hosts
       WHERE id = ?`,
    );

    const row = stmt.get(id);
    return row ? rowToHost(row) : undefined;
  }

  /** Return all Hosts. */
  findAll(): Host[] {
    const stmt = this.db.prepare<[], HostRow>(
      `SELECT id, authority_kind, authority, resolved_ips_json, created_at, updated_at
       FROM hosts`,
    );

    const rows = stmt.all();
    return rows.map(rowToHost);
  }

  /** Find a Host by its unique authority value. Returns undefined if not found. */
  findByAuthority(authority: string): Host | undefined {
    const stmt = this.db.prepare<[string], HostRow>(
      `SELECT id, authority_kind, authority, resolved_ips_json, created_at, updated_at
       FROM hosts
       WHERE authority = ?`,
    );

    const row = stmt.get(authority);
    return row ? rowToHost(row) : undefined;
  }

  /**
   * Update an existing Host with the provided fields.
   * Always bumps `updated_at`. Returns the updated entity, or undefined if
   * the Host was not found.
   */
  update(id: string, input: UpdateHostInput): Host | undefined {
    const setClauses: string[] = [];
    const params: unknown[] = [];

    if (input.resolvedIpsJson !== undefined) {
      setClauses.push('resolved_ips_json = ?');
      params.push(input.resolvedIpsJson);
    }

    const now = new Date().toISOString();
    setClauses.push('updated_at = ?');
    params.push(now);

    // Always include the WHERE id
    params.push(id);

    const sql = `UPDATE hosts SET ${setClauses.join(', ')} WHERE id = ?`;
    const stmt = this.db.prepare(sql);
    const result = stmt.run(...params);

    if (result.changes === 0) {
      return undefined;
    }

    return this.findById(id);
  }

  /** Delete a Host by id. Returns true if a row was deleted. */
  delete(id: string): boolean {
    const stmt = this.db.prepare<[string]>('DELETE FROM hosts WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }
}
