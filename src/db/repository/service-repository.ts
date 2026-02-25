import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { Service } from '../../types/entities.js';
import type { CreateServiceInput, UpdateServiceInput } from '../../types/repository.js';

/**
 * Raw row shape returned by better-sqlite3 for the `services` table.
 * Column names are snake_case as defined in the schema.
 */
interface ServiceRow {
  id: string;
  host_id: string;
  transport: string;
  port: number;
  app_proto: string;
  proto_confidence: string;
  banner: string | null;
  product: string | null;
  version: string | null;
  state: string;
  evidence_artifact_id: string;
  created_at: string;
  updated_at: string;
}

/** Maps a snake_case DB row to a camelCase Service entity. */
function rowToService(row: ServiceRow): Service {
  return {
    id: row.id,
    hostId: row.host_id,
    transport: row.transport,
    port: row.port,
    appProto: row.app_proto,
    protoConfidence: row.proto_confidence,
    banner: row.banner ?? undefined,
    product: row.product ?? undefined,
    version: row.version ?? undefined,
    state: row.state,
    evidenceArtifactId: row.evidence_artifact_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Repository for the `services` table.
 *
 * All queries use prepared statements to prevent SQL injection.
 */
export class ServiceRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /** Insert a new Service and return the full entity. */
  create(input: CreateServiceInput): Service {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const stmt = this.db.prepare<
      [string, string, string, number, string, string, string | null, string | null, string | null, string, string, string, string]
    >(
      `INSERT INTO services (id, host_id, transport, port, app_proto, proto_confidence, banner, product, version, state, evidence_artifact_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    stmt.run(
      id,
      input.hostId,
      input.transport,
      input.port,
      input.appProto,
      input.protoConfidence,
      input.banner ?? null,
      input.product ?? null,
      input.version ?? null,
      input.state,
      input.evidenceArtifactId,
      now,
      now,
    );

    return {
      id,
      hostId: input.hostId,
      transport: input.transport,
      port: input.port,
      appProto: input.appProto,
      protoConfidence: input.protoConfidence,
      banner: input.banner,
      product: input.product,
      version: input.version,
      state: input.state,
      evidenceArtifactId: input.evidenceArtifactId,
      createdAt: now,
      updatedAt: now,
    };
  }

  /** Find a Service by its primary key. Returns undefined if not found. */
  findById(id: string): Service | undefined {
    const stmt = this.db.prepare<[string], ServiceRow>(
      `SELECT id, host_id, transport, port, app_proto, proto_confidence, banner, product, version, state, evidence_artifact_id, created_at, updated_at
       FROM services
       WHERE id = ?`,
    );

    const row = stmt.get(id);
    return row ? rowToService(row) : undefined;
  }

  /** Find all Services belonging to a given host. */
  findByHostId(hostId: string): Service[] {
    const stmt = this.db.prepare<[string], ServiceRow>(
      `SELECT id, host_id, transport, port, app_proto, proto_confidence, banner, product, version, state, evidence_artifact_id, created_at, updated_at
       FROM services
       WHERE host_id = ?`,
    );

    const rows = stmt.all(hostId);
    return rows.map(rowToService);
  }

  /**
   * Update an existing Service with the provided fields.
   * Always bumps `updated_at`. Returns the updated entity, or undefined if
   * the Service was not found.
   */
  update(id: string, input: UpdateServiceInput): Service | undefined {
    const setClauses: string[] = [];
    const params: unknown[] = [];

    if (input.appProto !== undefined) {
      setClauses.push('app_proto = ?');
      params.push(input.appProto);
    }

    if (input.protoConfidence !== undefined) {
      setClauses.push('proto_confidence = ?');
      params.push(input.protoConfidence);
    }

    if (input.banner !== undefined) {
      setClauses.push('banner = ?');
      params.push(input.banner);
    }

    if (input.product !== undefined) {
      setClauses.push('product = ?');
      params.push(input.product);
    }

    if (input.version !== undefined) {
      setClauses.push('version = ?');
      params.push(input.version);
    }

    if (input.state !== undefined) {
      setClauses.push('state = ?');
      params.push(input.state);
    }

    const now = new Date().toISOString();
    setClauses.push('updated_at = ?');
    params.push(now);

    // Always include the WHERE id
    params.push(id);

    const sql = `UPDATE services SET ${setClauses.join(', ')} WHERE id = ?`;
    const stmt = this.db.prepare(sql);
    const result = stmt.run(...params);

    if (result.changes === 0) {
      return undefined;
    }

    return this.findById(id);
  }

  /** Delete a Service by id. Returns true if a row was deleted. */
  delete(id: string): boolean {
    const stmt = this.db.prepare<[string]>('DELETE FROM services WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }
}
