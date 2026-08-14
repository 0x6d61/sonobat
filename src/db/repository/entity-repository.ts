import { randomUUID } from 'node:crypto';
import type Database from 'better-sqlite3';
import type { Entity, Relation } from '../../types/domain.js';

interface EntityRow {
  id: string;
  kind: string;
  natural_key: string;
  props_json: string;
  artifact_id: string | null;
  created_at: string;
  updated_at: string;
}

interface RelationRow {
  id: string;
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

  upsert(input: { kind: string; naturalKey: string; properties?: unknown; artifactId?: string }): {
    entity: Entity;
    created: boolean;
  } {
    this.requireKind(input.kind);
    if (input.naturalKey.trim() === '') throw new Error('naturalKey must not be empty');
    const properties = requireObject(input.properties ?? {}, 'properties');
    const existing = this.findByNaturalKey(input.naturalKey);
    const now = new Date().toISOString();
    if (existing !== undefined) {
      if (existing.kind !== input.kind) throw new Error('naturalKey already uses another kind');
      this.db
        .prepare(
          'UPDATE entities SET props_json = ?, artifact_id = COALESCE(?, artifact_id), updated_at = ? WHERE id = ?',
        )
        .run(JSON.stringify(properties), input.artifactId ?? null, now, existing.id);
      return { entity: this.findById(existing.id)!, created: false };
    }
    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO entities
         (id, kind, natural_key, props_json, artifact_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.kind,
        input.naturalKey,
        JSON.stringify(properties),
        input.artifactId ?? null,
        now,
        now,
      );
    return { entity: this.findById(id)!, created: true };
  }

  findById(id: string): Entity | undefined {
    const row = this.db.prepare('SELECT * FROM entities WHERE id = ?').get(id) as
      | EntityRow
      | undefined;
    return row === undefined ? undefined : entityFromRow(row);
  }

  findByNaturalKey(naturalKey: string): Entity | undefined {
    const row = this.db.prepare('SELECT * FROM entities WHERE natural_key = ?').get(naturalKey) as
      | EntityRow
      | undefined;
    return row === undefined ? undefined : entityFromRow(row);
  }

  list(kind?: string): Entity[] {
    const rows = (
      kind === undefined
        ? this.db.prepare('SELECT * FROM entities ORDER BY created_at').all()
        : this.db.prepare('SELECT * FROM entities WHERE kind = ? ORDER BY created_at').all(kind)
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
    kind: string;
    sourceEntityId: string;
    targetEntityId: string;
    properties?: unknown;
    artifactId?: string;
  }): { relation: Relation; created: boolean } {
    this.requireKind(input.kind);
    const properties = requireObject(input.properties ?? {}, 'properties');
    const existing = this.db
      .prepare(
        `SELECT * FROM relations
         WHERE kind = ? AND source_entity_id = ? AND target_entity_id = ?`,
      )
      .get(input.kind, input.sourceEntityId, input.targetEntityId) as RelationRow | undefined;
    if (existing !== undefined) return { relation: relationFromRow(existing), created: false };
    const id = randomUUID();
    const createdAt = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO relations
         (id, kind, source_entity_id, target_entity_id, props_json, artifact_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.kind,
        input.sourceEntityId,
        input.targetEntityId,
        JSON.stringify(properties),
        input.artifactId ?? null,
        createdAt,
      );
    return { relation: this.findById(id)!, created: true };
  }

  findById(id: string): Relation | undefined {
    const row = this.db.prepare('SELECT * FROM relations WHERE id = ?').get(id) as
      | RelationRow
      | undefined;
    return row === undefined ? undefined : relationFromRow(row);
  }

  list(entityId?: string): Relation[] {
    const rows = (
      entityId === undefined
        ? this.db.prepare('SELECT * FROM relations ORDER BY created_at').all()
        : this.db
            .prepare(
              `SELECT * FROM relations
             WHERE source_entity_id = ? OR target_entity_id = ? ORDER BY created_at`,
            )
            .all(entityId, entityId)
    ) as RelationRow[];
    return rows.map(relationFromRow);
  }

  private requireKind(kind: string): void {
    const row = this.db.prepare('SELECT 1 FROM relation_kinds WHERE kind = ?').get(kind);
    if (row === undefined) throw new Error(`Unknown relation kind: ${kind}`);
  }
}
