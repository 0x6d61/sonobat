import type Database from 'better-sqlite3';
import type { ActionQueueItem, Mission } from '../../types/operational.js';
import type { GraphEdge, GraphNode } from '../../types/graph.js';
import { ActionQueueRepository } from './action-queue-repository.js';
import { MissionRepository } from './mission-repository.js';

export interface ActionContext {
  action: ActionQueueItem;
  mission?: Mission;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

interface ContextRow {
  node_id: string;
  node_kind: string;
  natural_key: string;
  node_props_json: string;
  node_evidence_artifact_id: string | null;
  node_created_at: string;
  node_updated_at: string;
  edge_id: string | null;
  edge_kind: string | null;
  source_id: string | null;
  target_id: string | null;
  edge_props_json: string | null;
  edge_evidence_artifact_id: string | null;
  edge_created_at: string | null;
}

export class ActionContextRepository {
  constructor(private readonly db: Database.Database) {}

  get(
    actionId: string,
    targetNodeIds: string[],
    options?: { edgeKinds?: string[]; depth?: number },
  ): ActionContext | undefined {
    const action = new ActionQueueRepository(this.db).findById(actionId);
    if (action === undefined) return undefined;
    const mission =
      action.missionId === undefined
        ? undefined
        : new MissionRepository(this.db).findById(action.missionId);
    if (targetNodeIds.length === 0)
      return { action, ...(mission ? { mission } : {}), nodes: [], edges: [] };

    const depth = Math.max(0, Math.min(options?.depth ?? 1, 10));
    const targetPlaceholders = targetNodeIds.map(() => '?').join(', ');
    const edgeKinds = options?.edgeKinds ?? [];
    const edgeFilter =
      edgeKinds.length === 0 ? '' : `AND e.kind IN (${edgeKinds.map(() => '?').join(', ')})`;
    const rows = this.db
      .prepare(
        `WITH RECURSIVE reachable(node_id, depth) AS (
           SELECT id, 0 FROM nodes WHERE id IN (${targetPlaceholders})
           UNION
           SELECT CASE WHEN e.source_id = r.node_id THEN e.target_id ELSE e.source_id END, r.depth + 1
           FROM reachable r
           JOIN edges e ON e.source_id = r.node_id OR e.target_id = r.node_id
           WHERE r.depth < ? ${edgeFilter}
         )
         SELECT n.id node_id, n.kind node_kind, n.natural_key, n.props_json node_props_json,
                n.evidence_artifact_id node_evidence_artifact_id,
                n.created_at node_created_at, n.updated_at node_updated_at,
                e.id edge_id, e.kind edge_kind, e.source_id, e.target_id,
                e.props_json edge_props_json, e.evidence_artifact_id edge_evidence_artifact_id,
                e.created_at edge_created_at
         FROM nodes n
         JOIN (SELECT DISTINCT node_id FROM reachable) r ON r.node_id = n.id
         LEFT JOIN edges e ON (e.source_id = n.id OR e.target_id = n.id)
           AND e.source_id IN (SELECT node_id FROM reachable)
           AND e.target_id IN (SELECT node_id FROM reachable)`,
      )
      .all(...targetNodeIds, depth, ...edgeKinds) as ContextRow[];

    const nodes = new Map<string, GraphNode>();
    const edges = new Map<string, GraphEdge>();
    for (const row of rows) {
      nodes.set(row.node_id, {
        id: row.node_id,
        kind: row.node_kind as GraphNode['kind'],
        naturalKey: row.natural_key,
        propsJson: row.node_props_json,
        ...(row.node_evidence_artifact_id === null
          ? {}
          : { evidenceArtifactId: row.node_evidence_artifact_id }),
        createdAt: row.node_created_at,
        updatedAt: row.node_updated_at,
      });
      if (row.edge_id !== null) {
        edges.set(row.edge_id, {
          id: row.edge_id,
          kind: row.edge_kind as GraphEdge['kind'],
          sourceId: row.source_id!,
          targetId: row.target_id!,
          propsJson: row.edge_props_json!,
          ...(row.edge_evidence_artifact_id === null
            ? {}
            : { evidenceArtifactId: row.edge_evidence_artifact_id }),
          createdAt: row.edge_created_at!,
        });
      }
    }
    return {
      action,
      ...(mission === undefined ? {} : { mission }),
      nodes: [...nodes.values()],
      edges: [...edges.values()],
    };
  }
}
