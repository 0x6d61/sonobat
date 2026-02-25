import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { Artifact } from '../../types/entities.js';
import type { CreateArtifactInput } from '../../types/repository.js';

/** Row shape returned by better-sqlite3 for the artifacts table. */
interface ArtifactRow {
  id: string;
  scan_id: string | null;
  tool: string;
  kind: string;
  path: string;
  sha256: string | null;
  captured_at: string;
  attrs_json: string | null;
}

/** Maps a snake_case DB row to a camelCase Artifact entity. */
function rowToArtifact(row: ArtifactRow): Artifact {
  return {
    id: row.id,
    ...(row.scan_id !== null ? { scanId: row.scan_id } : {}),
    tool: row.tool,
    kind: row.kind,
    path: row.path,
    ...(row.sha256 !== null ? { sha256: row.sha256 } : {}),
    capturedAt: row.captured_at,
    ...(row.attrs_json !== null ? { attrsJson: row.attrs_json } : {}),
  };
}

/**
 * Repository for the `artifacts` table.
 *
 * Provides CRUD operations with camelCase ↔ snake_case mapping
 * between the TypeScript entity layer and the SQLite storage layer.
 */
export class ArtifactRepository {
  private readonly db: Database.Database;

  private readonly insertStmt: Database.Statement;
  private readonly selectByIdStmt: Database.Statement;
  private readonly selectAllStmt: Database.Statement;
  private readonly selectByToolStmt: Database.Statement;

  constructor(db: Database.Database) {
    this.db = db;

    this.insertStmt = this.db.prepare(
      'INSERT INTO artifacts (id, scan_id, tool, kind, path, sha256, captured_at, attrs_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    );

    this.selectByIdStmt = this.db.prepare(
      'SELECT id, scan_id, tool, kind, path, sha256, captured_at, attrs_json FROM artifacts WHERE id = ?',
    );

    this.selectAllStmt = this.db.prepare(
      'SELECT id, scan_id, tool, kind, path, sha256, captured_at, attrs_json FROM artifacts',
    );

    this.selectByToolStmt = this.db.prepare(
      'SELECT id, scan_id, tool, kind, path, sha256, captured_at, attrs_json FROM artifacts WHERE tool = ?',
    );
  }

  /** Create a new Artifact record and return the full entity. */
  create(input: CreateArtifactInput): Artifact {
    const id = crypto.randomUUID();

    this.insertStmt.run(
      id,
      input.scanId ?? null,
      input.tool,
      input.kind,
      input.path,
      input.sha256 ?? null,
      input.capturedAt,
      input.attrsJson ?? null,
    );

    return {
      id,
      ...(input.scanId !== undefined ? { scanId: input.scanId } : {}),
      tool: input.tool,
      kind: input.kind,
      path: input.path,
      ...(input.sha256 !== undefined ? { sha256: input.sha256 } : {}),
      capturedAt: input.capturedAt,
      ...(input.attrsJson !== undefined ? { attrsJson: input.attrsJson } : {}),
    };
  }

  /** Find an Artifact by its UUID. Returns undefined if not found. */
  findById(id: string): Artifact | undefined {
    const row = this.selectByIdStmt.get(id) as ArtifactRow | undefined;
    if (row === undefined) {
      return undefined;
    }
    return rowToArtifact(row);
  }

  /** Return all Artifact records. */
  findAll(): Artifact[] {
    const rows = this.selectAllStmt.all() as ArtifactRow[];
    return rows.map(rowToArtifact);
  }

  /** Return all Artifact records for the given tool name. */
  findByTool(tool: string): Artifact[] {
    const rows = this.selectByToolStmt.all(tool) as ArtifactRow[];
    return rows.map(rowToArtifact);
  }
}
