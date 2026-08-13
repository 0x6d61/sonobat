import type Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';
import type { Artifact } from '../../types/operational.js';

interface ArtifactRow {
  id: string;
  engagement_id: string | null;
  run_id: string | null;
  mission_id: string | null;
  action_id: string | null;
  action_execution_id: string | null;
  tool: string;
  kind: string;
  path: string;
  sha256: string | null;
  media_type: string | null;
  sensitivity: string;
  attrs_json: string | null;
  captured_at: string;
}

function toArtifact(row: ArtifactRow): Artifact {
  return {
    id: row.id,
    ...(row.engagement_id === null ? {} : { engagementId: row.engagement_id }),
    ...(row.run_id === null ? {} : { runId: row.run_id }),
    ...(row.mission_id === null ? {} : { missionId: row.mission_id }),
    ...(row.action_id === null ? {} : { actionId: row.action_id }),
    ...(row.action_execution_id === null ? {} : { actionExecutionId: row.action_execution_id }),
    producer: row.tool,
    kind: row.kind,
    path: row.path,
    ...(row.sha256 === null ? {} : { sha256: row.sha256 }),
    ...(row.media_type === null ? {} : { mediaType: row.media_type }),
    sensitivity: row.sensitivity,
    attrsJson: row.attrs_json ?? '{}',
    capturedAt: row.captured_at,
  };
}

export class ArtifactRepository {
  constructor(private readonly db: Database.Database) {}

  create(input: {
    engagementId: string;
    runId?: string;
    missionId?: string;
    actionId: string;
    actionExecutionId: string;
    producer: string;
    kind: string;
    path: string;
    sha256?: string;
    mediaType?: string;
    sensitivity?: string;
    attrsJson?: string;
  }): Artifact {
    if (input.kind.trim() === '' || input.path.trim() === '') {
      throw new Error('Artifact kind and path must not be empty');
    }
    const attrs: unknown = JSON.parse(input.attrsJson ?? '{}');
    if (attrs === null || Array.isArray(attrs) || typeof attrs !== 'object') {
      throw new Error('attrsJson must be a JSON object');
    }
    const id = randomUUID();
    const capturedAt = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO artifacts
         (id, tool, kind, path, sha256, captured_at, attrs_json, engagement_id, run_id,
          mission_id, action_id, action_execution_id, media_type, sensitivity)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.producer,
        input.kind,
        input.path,
        input.sha256 ?? null,
        capturedAt,
        JSON.stringify(attrs),
        input.engagementId,
        input.runId ?? null,
        input.missionId ?? null,
        input.actionId,
        input.actionExecutionId,
        input.mediaType ?? null,
        input.sensitivity ?? 'internal',
      );
    return this.findById(id)!;
  }

  findById(id: string): Artifact | undefined {
    const row = this.db.prepare('SELECT * FROM artifacts WHERE id = ?').get(id) as
      | ArtifactRow
      | undefined;
    return row === undefined ? undefined : toArtifact(row);
  }
}
