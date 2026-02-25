import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { Vhost } from '../../types/entities.js';
import type { CreateVhostInput } from '../../types/repository.js';

/**
 * Raw row shape returned by better-sqlite3 for the `vhosts` table.
 * Column names are snake_case as defined in the schema.
 */
interface VhostRow {
  id: string;
  host_id: string;
  hostname: string;
  source: string | null;
  evidence_artifact_id: string;
  created_at: string;
}

/** Maps a snake_case DB row to a camelCase Vhost entity. */
function rowToVhost(row: VhostRow): Vhost {
  return {
    id: row.id,
    hostId: row.host_id,
    hostname: row.hostname,
    source: row.source ?? undefined,
    evidenceArtifactId: row.evidence_artifact_id,
    createdAt: row.created_at,
  };
}

/**
 * Repository for the `vhosts` table.
 *
 * All queries use prepared statements to prevent SQL injection.
 */
export class VhostRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /** Insert a new Vhost and return the full entity. */
  create(input: CreateVhostInput): Vhost {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const stmt = this.db.prepare<
      [string, string, string, string | null, string, string]
    >(
      `INSERT INTO vhosts (id, host_id, hostname, source, evidence_artifact_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    );

    stmt.run(
      id,
      input.hostId,
      input.hostname,
      input.source ?? null,
      input.evidenceArtifactId,
      now,
    );

    return {
      id,
      hostId: input.hostId,
      hostname: input.hostname,
      source: input.source,
      evidenceArtifactId: input.evidenceArtifactId,
      createdAt: now,
    };
  }

  /** Find a Vhost by its primary key. Returns undefined if not found. */
  findById(id: string): Vhost | undefined {
    const stmt = this.db.prepare<[string], VhostRow>(
      `SELECT id, host_id, hostname, source, evidence_artifact_id, created_at
       FROM vhosts
       WHERE id = ?`,
    );

    const row = stmt.get(id);
    return row ? rowToVhost(row) : undefined;
  }

  /** Return all Vhosts belonging to a given host. */
  findByHostId(hostId: string): Vhost[] {
    const stmt = this.db.prepare<[string], VhostRow>(
      `SELECT id, host_id, hostname, source, evidence_artifact_id, created_at
       FROM vhosts
       WHERE host_id = ?`,
    );

    const rows = stmt.all(hostId);
    return rows.map(rowToVhost);
  }

  /** Delete a Vhost by id. Returns true if a row was deleted. */
  delete(id: string): boolean {
    const stmt = this.db.prepare<[string]>('DELETE FROM vhosts WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }
}
