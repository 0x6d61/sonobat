import type Database from 'better-sqlite3';
import type {
  ActionExecution,
  ActionQueueItem,
  Artifact,
  Engagement,
  Finding,
  Mission,
  ObservationRecord,
} from '../../types/operational.js';
import type { GraphEdge, GraphNode } from '../../types/graph.js';
import { ActionQueueRepository } from './action-queue-repository.js';
import { MissionRepository } from './mission-repository.js';
import { EngagementRepository } from './engagement-repository.js';
import { ActionExecutionRepository } from './action-execution-repository.js';
import { ArtifactRepository } from './artifact-repository.js';
import { FindingRepository } from './finding-repository.js';
import { ObservationRepository } from './observation-repository.js';

export interface ActionContext {
  action: ActionQueueItem;
  mission?: Mission;
  engagement: Engagement;
  parentAction?: ActionQueueItem;
  executions: ActionExecution[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  observations: ObservationRecord[];
  artifacts: Artifact[];
  findings: Finding[];
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
    options?: { edgeKinds?: string[]; depth?: number; includeSensitive?: boolean },
  ): ActionContext | undefined {
    const action = new ActionQueueRepository(this.db).findById(actionId);
    if (action === undefined) return undefined;
    const mission =
      action.missionId === undefined
        ? undefined
        : new MissionRepository(this.db).findById(action.missionId);
    const engagement = new EngagementRepository(this.db).findById(action.engagementId);
    if (engagement === undefined) throw new Error(`Engagement not found: ${action.engagementId}`);
    const parentAction =
      action.parentActionId === undefined
        ? undefined
        : new ActionQueueRepository(this.db).findById(action.parentActionId);
    const executions = new ActionExecutionRepository(this.db).findByAction(action.id);
    if (targetNodeIds.length === 0) {
      return {
        action,
        ...(mission ? { mission } : {}),
        engagement,
        ...(parentAction ? { parentAction } : {}),
        executions,
        nodes: [],
        edges: [],
        observations: [],
        artifacts: this.findArtifacts(action.id, executions),
        findings: [],
      };
    }

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
    if (options?.includeSensitive !== true) {
      const credentialIds = [...nodes.values()]
        .filter((node) => node.kind === 'credential')
        .map((node) => node.id);
      for (const id of credentialIds) nodes.delete(id);
      for (const [id, edge] of edges) {
        if (credentialIds.includes(edge.sourceId) || credentialIds.includes(edge.targetId)) {
          edges.delete(id);
        }
      }
    }
    const nodeIds = [...nodes.keys()];
    const edgeIds = [...edges.keys()];
    const observationIds = this.findObservationIds(nodeIds, edgeIds);
    const observationRepo = new ObservationRepository(this.db);
    const observations = observationIds
      .map((id) => observationRepo.findById(id))
      .filter((value): value is ObservationRecord => value !== undefined);
    const artifactIds = new Set(observations.map((item) => item.artifactId));
    for (const node of nodes.values())
      if (node.evidenceArtifactId) artifactIds.add(node.evidenceArtifactId);
    for (const edge of edges.values())
      if (edge.evidenceArtifactId) artifactIds.add(edge.evidenceArtifactId);
    for (const artifact of this.findArtifacts(action.id, executions)) artifactIds.add(artifact.id);
    const artifactRepo = new ArtifactRepository(this.db);
    const artifacts = [...artifactIds]
      .map((id) => artifactRepo.findById(id, { includeSensitive: true }))
      .filter((value): value is Artifact => value !== undefined)
      .filter(
        (artifact) => options?.includeSensitive === true || artifact.sensitivity !== 'secret',
      );
    const findingRows = this.db
      .prepare(
        `SELECT DISTINCT f.id FROM findings f
         LEFT JOIN observation_findings ofn ON ofn.finding_id = f.id
         WHERE f.engagement_id = ? AND (f.node_id IN (${nodeIds.map(() => '?').join(', ')})
           OR ofn.observation_id IN (${observationIds.length === 0 ? "''" : observationIds.map(() => '?').join(', ')}))`,
      )
      .all(action.engagementId, ...nodeIds, ...observationIds) as Array<{ id: string }>;
    const findingRepo = new FindingRepository(this.db);
    const findings = findingRows
      .map((row) => findingRepo.findById(row.id))
      .filter((value): value is Finding => value !== undefined);
    return {
      action,
      ...(mission === undefined ? {} : { mission }),
      engagement,
      ...(parentAction === undefined ? {} : { parentAction }),
      executions,
      nodes: [...nodes.values()],
      edges: [...edges.values()],
      observations,
      artifacts,
      findings,
    };
  }

  private findObservationIds(nodeIds: string[], edgeIds: string[]): string[] {
    const ids = new Set<string>();
    if (nodeIds.length > 0) {
      const rows = this.db
        .prepare(
          `SELECT observation_id FROM observation_nodes WHERE node_id IN (${nodeIds.map(() => '?').join(', ')})`,
        )
        .all(...nodeIds) as Array<{ observation_id: string }>;
      for (const row of rows) ids.add(row.observation_id);
    }
    if (edgeIds.length > 0) {
      const rows = this.db
        .prepare(
          `SELECT observation_id FROM observation_edges WHERE edge_id IN (${edgeIds.map(() => '?').join(', ')})`,
        )
        .all(...edgeIds) as Array<{ observation_id: string }>;
      for (const row of rows) ids.add(row.observation_id);
    }
    return [...ids];
  }

  private findArtifacts(actionId: string, executions: ActionExecution[]): Artifact[] {
    const executionIds = executions.map((item) => item.id);
    const rows = this.db
      .prepare(
        `SELECT id FROM artifacts WHERE action_id = ?${
          executionIds.length === 0
            ? ''
            : ` OR action_execution_id IN (${executionIds.map(() => '?').join(', ')})`
        }`,
      )
      .all(actionId, ...executionIds) as Array<{ id: string }>;
    const repo = new ArtifactRepository(this.db);
    return rows
      .map((row) => repo.findById(row.id, { includeSensitive: true }))
      .filter((value): value is Artifact => value !== undefined);
  }
}
