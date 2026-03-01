import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { EdgeKind, GraphEdge } from '../../types/graph.js';

/** Row shape returned by better-sqlite3 for the edges table. */
interface EdgeRow {
  id: string;
  kind: string;
  source_id: string;
  target_id: string;
  props_json: string;
  evidence_artifact_id: string | null;
  created_at: string;
}

/** Maps a snake_case DB row to a camelCase GraphEdge entity. */
function rowToEdge(row: EdgeRow): GraphEdge {
  return {
    id: row.id,
    kind: row.kind as EdgeKind,
    sourceId: row.source_id,
    targetId: row.target_id,
    propsJson: row.props_json,
    ...(row.evidence_artifact_id !== null ? { evidenceArtifactId: row.evidence_artifact_id } : {}),
    createdAt: row.created_at,
  };
}

/**
 * Repository for the `edges` table.
 *
 * Provides CRUD operations with camelCase <-> snake_case mapping
 * between the TypeScript entity layer and the SQLite storage layer.
 */
export class EdgeRepository {
  private readonly db: Database.Database;

  private readonly insertStmt: Database.Statement;
  private readonly selectByCompositeKeyStmt: Database.Statement;
  private readonly selectBySourceStmt: Database.Statement;
  private readonly selectBySourceAndKindStmt: Database.Statement;
  private readonly selectByTargetStmt: Database.Statement;
  private readonly selectByTargetAndKindStmt: Database.Statement;
  private readonly selectByKindStmt: Database.Statement;
  private readonly deleteStmt: Database.Statement;

  constructor(db: Database.Database) {
    this.db = db;

    this.insertStmt = this.db.prepare(
      'INSERT INTO edges (id, kind, source_id, target_id, props_json, evidence_artifact_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    );

    this.selectByCompositeKeyStmt = this.db.prepare(
      'SELECT id, kind, source_id, target_id, props_json, evidence_artifact_id, created_at FROM edges WHERE kind = ? AND source_id = ? AND target_id = ?',
    );

    this.selectBySourceStmt = this.db.prepare(
      'SELECT id, kind, source_id, target_id, props_json, evidence_artifact_id, created_at FROM edges WHERE source_id = ?',
    );

    this.selectBySourceAndKindStmt = this.db.prepare(
      'SELECT id, kind, source_id, target_id, props_json, evidence_artifact_id, created_at FROM edges WHERE source_id = ? AND kind = ?',
    );

    this.selectByTargetStmt = this.db.prepare(
      'SELECT id, kind, source_id, target_id, props_json, evidence_artifact_id, created_at FROM edges WHERE target_id = ?',
    );

    this.selectByTargetAndKindStmt = this.db.prepare(
      'SELECT id, kind, source_id, target_id, props_json, evidence_artifact_id, created_at FROM edges WHERE target_id = ? AND kind = ?',
    );

    this.selectByKindStmt = this.db.prepare(
      'SELECT id, kind, source_id, target_id, props_json, evidence_artifact_id, created_at FROM edges WHERE kind = ?',
    );

    this.deleteStmt = this.db.prepare('DELETE FROM edges WHERE id = ?');
  }

  /**
   * Create a new edge linking two nodes.
   *
   * Throws if the (kind, source_id, target_id) combination already exists.
   */
  create(
    kind: EdgeKind,
    sourceId: string,
    targetId: string,
    evidenceArtifactId?: string,
    propsJson?: string,
  ): GraphEdge {
    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    const props = propsJson ?? '{}';

    this.insertStmt.run(id, kind, sourceId, targetId, props, evidenceArtifactId ?? null, createdAt);

    return {
      id,
      kind,
      sourceId,
      targetId,
      propsJson: props,
      ...(evidenceArtifactId !== undefined ? { evidenceArtifactId } : {}),
      createdAt,
    };
  }

  /**
   * Upsert an edge by (kind, source_id, target_id).
   *
   * If the combination already exists, returns the existing edge with `created: false`.
   * Otherwise creates a new edge and returns it with `created: true`.
   */
  upsert(
    kind: EdgeKind,
    sourceId: string,
    targetId: string,
    evidenceArtifactId?: string,
    propsJson?: string,
  ): { edge: GraphEdge; created: boolean } {
    const existing = this.selectByCompositeKeyStmt.get(kind, sourceId, targetId) as
      | EdgeRow
      | undefined;

    if (existing !== undefined) {
      return { edge: rowToEdge(existing), created: false };
    }

    const edge = this.create(kind, sourceId, targetId, evidenceArtifactId, propsJson);
    return { edge, created: true };
  }

  /**
   * Find all edges originating from a source node.
   *
   * Optionally filter by edge kind.
   */
  findBySource(sourceId: string, edgeKind?: EdgeKind): GraphEdge[] {
    if (edgeKind !== undefined) {
      const rows = this.selectBySourceAndKindStmt.all(sourceId, edgeKind) as EdgeRow[];
      return rows.map(rowToEdge);
    }
    const rows = this.selectBySourceStmt.all(sourceId) as EdgeRow[];
    return rows.map(rowToEdge);
  }

  /**
   * Find all edges targeting a node.
   *
   * Optionally filter by edge kind.
   */
  findByTarget(targetId: string, edgeKind?: EdgeKind): GraphEdge[] {
    if (edgeKind !== undefined) {
      const rows = this.selectByTargetAndKindStmt.all(targetId, edgeKind) as EdgeRow[];
      return rows.map(rowToEdge);
    }
    const rows = this.selectByTargetStmt.all(targetId) as EdgeRow[];
    return rows.map(rowToEdge);
  }

  /**
   * Find all edges of a specific kind.
   */
  findByKind(kind: EdgeKind): GraphEdge[] {
    const rows = this.selectByKindStmt.all(kind) as EdgeRow[];
    return rows.map(rowToEdge);
  }

  /**
   * Delete an edge by ID.
   *
   * Returns true if the edge was found and deleted, false otherwise.
   */
  delete(id: string): boolean {
    const result = this.deleteStmt.run(id);
    return result.changes > 0;
  }
}
