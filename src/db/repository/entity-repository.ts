import { randomUUID } from 'node:crypto';
import type Database from 'better-sqlite3';
import type { Entity, Relation } from '../../types/domain.js';
import { resolveAssessmentId } from './assessment-scope.js';

interface EntityRow {
  id: string;
  assessment_id: string;
  kind: string;
  natural_key: string;
  props_json: string;
  artifact_id: string | null;
  created_at: string;
  updated_at: string;
}

interface RelationRow {
  id: string;
  assessment_id: string;
  kind: string;
  source_entity_id: string;
  target_entity_id: string;
  props_json: string;
  artifact_id: string | null;
  created_at: string;
}

function entityFromRow(row: EntityRow): Entity {
  return {
    id: row.id,
    assessmentId: row.assessment_id,
    kind: row.kind,
    naturalKey: row.natural_key,
    properties: JSON.parse(row.props_json) as Record<string, unknown>,
    ...(row.artifact_id === null ? {} : { artifactId: row.artifact_id }),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function relationFromRow(row: RelationRow): Relation {
  return {
    id: row.id,
    assessmentId: row.assessment_id,
    kind: row.kind,
    sourceEntityId: row.source_entity_id,
    targetEntityId: row.target_entity_id,
    properties: JSON.parse(row.props_json) as Record<string, unknown>,
    ...(row.artifact_id === null ? {} : { artifactId: row.artifact_id }),
    createdAt: row.created_at,
  };
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

export class EntityRepository {
  constructor(private readonly db: Database.Database) {}

  upsert(input: {
    assessmentId?: string;
    kind: string;
    naturalKey: string;
    properties?: unknown;
    artifactId?: string;
  }): { entity: Entity; created: boolean } {
    const assessmentId = resolveAssessmentId(this.db, input.assessmentId);
    this.requireKind(input.kind);
    if (input.naturalKey.trim() === '') throw new Error('naturalKey must not be empty');
    const properties = requireObject(input.properties ?? {}, 'properties');
    const existing = this.findByNaturalKey(input.naturalKey, assessmentId);
    const now = new Date().toISOString();
    if (existing !== undefined) {
      if (existing.kind !== input.kind) throw new Error('naturalKey already uses another kind');
      this.db
        .prepare(
          'UPDATE entities SET props_json = ?, artifact_id = COALESCE(?, artifact_id), updated_at = ? WHERE id = ? AND assessment_id = ?',
        )
        .run(JSON.stringify(properties), input.artifactId ?? null, now, existing.id, assessmentId);
      return { entity: this.findById(existing.id, assessmentId)!, created: false };
    }
    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO entities
         (id, assessment_id, kind, natural_key, props_json, artifact_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        assessmentId,
        input.kind,
        input.naturalKey,
        JSON.stringify(properties),
        input.artifactId ?? null,
        now,
        now,
      );
    return { entity: this.findById(id, assessmentId)!, created: true };
  }

  findById(id: string, assessmentId?: string): Entity | undefined {
    const scope = resolveAssessmentId(this.db, assessmentId);
    const row = this.db
      .prepare('SELECT * FROM entities WHERE assessment_id = ? AND id = ?')
      .get(scope, id) as EntityRow | undefined;
    return row === undefined ? undefined : entityFromRow(row);
  }

  findByNaturalKey(naturalKey: string, assessmentId?: string): Entity | undefined {
    const scope = resolveAssessmentId(this.db, assessmentId);
    const row = this.db
      .prepare('SELECT * FROM entities WHERE assessment_id = ? AND natural_key = ?')
      .get(scope, naturalKey) as EntityRow | undefined;
    return row === undefined ? undefined : entityFromRow(row);
  }

  list(assessmentId?: string, kind?: string): Entity[] {
    const scope = resolveAssessmentId(this.db, assessmentId);
    const rows = (
      kind === undefined
        ? this.db
            .prepare('SELECT * FROM entities WHERE assessment_id = ? ORDER BY created_at')
            .all(scope)
        : this.db
            .prepare(
              'SELECT * FROM entities WHERE assessment_id = ? AND kind = ? ORDER BY created_at',
            )
            .all(scope, kind)
    ) as EntityRow[];
    return rows.map(entityFromRow);
  }

  private requireKind(kind: string): void {
    const row = this.db.prepare('SELECT 1 FROM entity_kinds WHERE kind = ?').get(kind);
    if (row === undefined) throw new Error(`Unknown entity kind: ${kind}`);
  }
}

export class RelationRepository {
  constructor(private readonly db: Database.Database) {}

  upsert(input: {
    assessmentId?: string;
    kind: string;
    sourceEntityId: string;
    targetEntityId: string;
    properties?: unknown;
    artifactId?: string;
  }): { relation: Relation; created: boolean } {
    const assessmentId = resolveAssessmentId(this.db, input.assessmentId);
    this.requireKind(input.kind);
    const properties = requireObject(input.properties ?? {}, 'properties');
    const source = this.entityAssessment(input.sourceEntityId);
    const target = this.entityAssessment(input.targetEntityId);
    if (source === undefined) throw new Error(`Source Entity not found: ${input.sourceEntityId}`);
    if (target === undefined) throw new Error(`Target Entity not found: ${input.targetEntityId}`);
    if (source !== target) throw new Error('Relation entities must belong to the same Assessment');
    if (source !== assessmentId) throw new Error('Relation entities are outside the Assessment');

    const existing = this.db
      .prepare(
        `SELECT * FROM relations
         WHERE assessment_id = ? AND kind = ? AND source_entity_id = ? AND target_entity_id = ?`,
      )
      .get(assessmentId, input.kind, input.sourceEntityId, input.targetEntityId) as
      | RelationRow
      | undefined;
    if (existing !== undefined) return { relation: relationFromRow(existing), created: false };
    const id = randomUUID();
    const createdAt = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO relations
         (id, assessment_id, kind, source_entity_id, target_entity_id, props_json, artifact_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        assessmentId,
        input.kind,
        input.sourceEntityId,
        input.targetEntityId,
        JSON.stringify(properties),
        input.artifactId ?? null,
        createdAt,
      );
    return { relation: this.findById(id, assessmentId)!, created: true };
  }

  findById(id: string, assessmentId?: string): Relation | undefined {
    const scope = resolveAssessmentId(this.db, assessmentId);
    const row = this.db
      .prepare('SELECT * FROM relations WHERE assessment_id = ? AND id = ?')
      .get(scope, id) as RelationRow | undefined;
    return row === undefined ? undefined : relationFromRow(row);
  }

  list(entityId?: string, assessmentId?: string): Relation[] {
    const scope = resolveAssessmentId(this.db, assessmentId);
    const rows = (
      entityId === undefined
        ? this.db
            .prepare('SELECT * FROM relations WHERE assessment_id = ? ORDER BY created_at')
            .all(scope)
        : this.db
            .prepare(
              `SELECT * FROM relations
               WHERE assessment_id = ? AND (source_entity_id = ? OR target_entity_id = ?)
               ORDER BY created_at`,
            )
            .all(scope, entityId, entityId)
    ) as RelationRow[];
    return rows.map(relationFromRow);
  }

  private entityAssessment(id: string): string | undefined {
    const row = this.db.prepare('SELECT assessment_id FROM entities WHERE id = ?').get(id) as
      | { assessment_id: string }
      | undefined;
    return row?.assessment_id;
  }

  private requireKind(kind: string): void {
    const row = this.db.prepare('SELECT 1 FROM relation_kinds WHERE kind = ?').get(kind);
    if (row === undefined) throw new Error(`Unknown relation kind: ${kind}`);
  }
}
