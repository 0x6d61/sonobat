import type Database from 'better-sqlite3';
import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { buildNaturalKey, EDGE_KINDS, NODE_KINDS, validateProps } from '../../types/graph.js';
import type { EdgeKind, NodeKind } from '../../types/graph.js';
import type { ObservationRecord } from '../../types/operational.js';

const ObservationInputSchema = z.object({
  artifactId: z.string().min(1),
  actor: z.string().min(1),
  content: z.unknown(),
  confidence: z.number().min(0).max(1).optional(),
  nodes: z
    .array(
      z.object({
        ref: z.string().min(1),
        kind: z.string().min(1),
        props: z.record(z.string(), z.unknown()),
        parentRef: z.string().optional(),
      }),
    )
    .default([]),
  edges: z
    .array(
      z.object({
        kind: z.string().min(1),
        sourceRef: z.string().min(1),
        targetRef: z.string().min(1),
        props: z.record(z.string(), z.unknown()).default({}),
      }),
    )
    .default([]),
  findingIds: z.array(z.string().min(1)).default([]),
});

export type CreateObservationInput = z.input<typeof ObservationInputSchema>;

interface ObservationRow {
  id: string;
  artifact_id: string;
  actor: string;
  content_json: string;
  confidence: number | null;
  created_at: string;
}

export class ObservationRepository {
  private readonly recordTx: (input: CreateObservationInput) => ObservationRecord;

  constructor(private readonly db: Database.Database) {
    this.recordTx = this.db.transaction((rawInput: CreateObservationInput): ObservationRecord => {
      const input = ObservationInputSchema.parse(rawInput);
      const dedupeKey = createHash('sha256').update(JSON.stringify(input)).digest('hex');
      const existing = this.db
        .prepare('SELECT id FROM observations WHERE dedupe_key = ?')
        .get(dedupeKey) as { id: string } | undefined;
      if (existing !== undefined) return this.findById(existing.id)!;
      const observationId = randomUUID();
      const createdAt = new Date().toISOString();
      this.db
        .prepare(
          `INSERT INTO observations
           (id, artifact_id, actor, dedupe_key, content_json, confidence, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          observationId,
          input.artifactId,
          input.actor,
          dedupeKey,
          JSON.stringify(input.content),
          input.confidence ?? null,
          createdAt,
        );

      const refs = new Map<string, string>();
      const nodeIds: string[] = [];
      for (const nodeInput of input.nodes) {
        if (refs.has(nodeInput.ref)) throw new Error(`Duplicate node ref: ${nodeInput.ref}`);
        if (!NODE_KINDS.includes(nodeInput.kind as NodeKind)) {
          throw new Error(`Unknown node kind: ${nodeInput.kind}`);
        }
        const kind = nodeInput.kind as NodeKind;
        const validation = validateProps(kind, nodeInput.props);
        if (!validation.ok) throw new Error(`Invalid ${kind} node: ${validation.error}`);
        const parentId =
          nodeInput.parentRef === undefined ? undefined : refs.get(nodeInput.parentRef);
        if (nodeInput.parentRef !== undefined && parentId === undefined) {
          throw new Error(`Unknown parent ref: ${nodeInput.parentRef}`);
        }
        const naturalKey = buildNaturalKey(kind, validation.data, parentId);
        const existing = this.db
          .prepare('SELECT id FROM nodes WHERE natural_key = ?')
          .get(naturalKey) as { id: string } | undefined;
        const nodeId = existing?.id ?? randomUUID();
        if (existing === undefined) {
          this.db
            .prepare(
              `INSERT INTO nodes
               (id, kind, natural_key, props_json, evidence_artifact_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)`,
            )
            .run(
              nodeId,
              kind,
              naturalKey,
              JSON.stringify(validation.data),
              input.artifactId,
              createdAt,
              createdAt,
            );
        }
        refs.set(nodeInput.ref, nodeId);
        nodeIds.push(nodeId);
        this.db
          .prepare('INSERT INTO observation_nodes (observation_id, node_id) VALUES (?, ?)')
          .run(observationId, nodeId);
      }

      const edgeIds: string[] = [];
      for (const edgeInput of input.edges) {
        if (!EDGE_KINDS.includes(edgeInput.kind as EdgeKind)) {
          throw new Error(`Unknown edge kind: ${edgeInput.kind}`);
        }
        const sourceId = refs.get(edgeInput.sourceRef) ?? edgeInput.sourceRef;
        const targetId = refs.get(edgeInput.targetRef) ?? edgeInput.targetRef;
        const existing = this.db
          .prepare('SELECT id FROM edges WHERE kind = ? AND source_id = ? AND target_id = ?')
          .get(edgeInput.kind, sourceId, targetId) as { id: string } | undefined;
        const edgeId = existing?.id ?? randomUUID();
        if (existing === undefined) {
          this.db
            .prepare(
              `INSERT INTO edges
               (id, kind, source_id, target_id, props_json, evidence_artifact_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)`,
            )
            .run(
              edgeId,
              edgeInput.kind as EdgeKind,
              sourceId,
              targetId,
              JSON.stringify(edgeInput.props),
              input.artifactId,
              createdAt,
            );
        }
        edgeIds.push(edgeId);
        this.db
          .prepare('INSERT INTO observation_edges (observation_id, edge_id) VALUES (?, ?)')
          .run(observationId, edgeId);
      }

      for (const findingId of input.findingIds) {
        this.db
          .prepare('INSERT INTO observation_findings (observation_id, finding_id) VALUES (?, ?)')
          .run(observationId, findingId);
      }

      return {
        id: observationId,
        artifactId: input.artifactId,
        actor: input.actor,
        contentJson: JSON.stringify(input.content),
        ...(input.confidence === undefined ? {} : { confidence: input.confidence }),
        nodeIds,
        edgeIds,
        findingIds: input.findingIds,
        createdAt,
      };
    });
  }

  record(input: CreateObservationInput): ObservationRecord {
    return this.recordTx(input);
  }

  findById(id: string): ObservationRecord | undefined {
    const row = this.db.prepare('SELECT * FROM observations WHERE id = ?').get(id) as
      | ObservationRow
      | undefined;
    if (row === undefined) return undefined;
    const nodeIds = this.db
      .prepare('SELECT node_id FROM observation_nodes WHERE observation_id = ?')
      .all(id) as Array<{ node_id: string }>;
    const edgeIds = this.db
      .prepare('SELECT edge_id FROM observation_edges WHERE observation_id = ?')
      .all(id) as Array<{ edge_id: string }>;
    const findingIds = this.db
      .prepare('SELECT finding_id FROM observation_findings WHERE observation_id = ?')
      .all(id) as Array<{ finding_id: string }>;
    return {
      id: row.id,
      artifactId: row.artifact_id,
      actor: row.actor,
      contentJson: row.content_json,
      ...(row.confidence === null ? {} : { confidence: row.confidence }),
      nodeIds: nodeIds.map((item) => item.node_id),
      edgeIds: edgeIds.map((item) => item.edge_id),
      findingIds: findingIds.map((item) => item.finding_id),
      createdAt: row.created_at,
    };
  }
}
