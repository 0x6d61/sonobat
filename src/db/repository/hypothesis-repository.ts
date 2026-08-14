import { randomUUID } from 'node:crypto';
import type Database from 'better-sqlite3';
import type { AttackHypothesis } from '../../types/domain.js';

interface HypothesisRow {
  id: string;
  engagement_id: string;
  mission_id: string | null;
  title: string;
  objective: string;
  status: string;
  preconditions_json: string;
  blockers_json: string;
  validation_result_json: string;
  dismissal_reason: string | null;
  artifact_id: string | null;
  created_at: string;
  updated_at: string;
}

function fromRow(row: HypothesisRow): AttackHypothesis {
  return {
    id: row.id,
    engagementId: row.engagement_id,
    ...(row.mission_id === null ? {} : { missionId: row.mission_id }),
    title: row.title,
    objective: row.objective,
    status: row.status,
    preconditions: JSON.parse(row.preconditions_json) as unknown[],
    blockers: JSON.parse(row.blockers_json) as unknown[],
    validationResult: JSON.parse(row.validation_result_json) as Record<string, unknown>,
    ...(row.dismissal_reason === null ? {} : { dismissalReason: row.dismissal_reason }),
    ...(row.artifact_id === null ? {} : { artifactId: row.artifact_id }),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class HypothesisRepository {
  constructor(private readonly db: Database.Database) {}

  create(input: {
    engagementId: string;
    missionId?: string;
    title: string;
    objective: string;
    preconditions?: unknown[];
    blockers?: unknown[];
    artifactId?: string;
  }): AttackHypothesis {
    const id = randomUUID();
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO attack_hypotheses
         (id, engagement_id, mission_id, title, objective, preconditions_json,
          blockers_json, artifact_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.engagementId,
        input.missionId ?? null,
        input.title,
        input.objective,
        JSON.stringify(input.preconditions ?? []),
        JSON.stringify(input.blockers ?? []),
        input.artifactId ?? null,
        now,
        now,
      );
    return this.findById(id)!;
  }

  findById(id: string): AttackHypothesis | undefined {
    const row = this.db.prepare('SELECT * FROM attack_hypotheses WHERE id = ?').get(id) as
      | HypothesisRow
      | undefined;
    return row === undefined ? undefined : fromRow(row);
  }

  list(engagementId: string): AttackHypothesis[] {
    return (
      this.db
        .prepare('SELECT * FROM attack_hypotheses WHERE engagement_id = ? ORDER BY updated_at DESC')
        .all(engagementId) as HypothesisRow[]
    ).map(fromRow);
  }

  evaluate(input: {
    id: string;
    status: 'active' | 'validated' | 'rejected' | 'dismissed';
    validationResult?: Record<string, unknown>;
    reason?: string;
    artifactId?: string;
  }): AttackHypothesis {
    const now = new Date().toISOString();
    const current = this.findById(input.id);
    if (current === undefined) throw new Error(`Hypothesis not found: ${input.id}`);
    const result = input.validationResult ?? current.validationResult;
    this.db.transaction(() => {
      this.db
        .prepare(
          `UPDATE attack_hypotheses SET status = ?, validation_result_json = ?,
           dismissal_reason = ?, artifact_id = COALESCE(?, artifact_id), updated_at = ? WHERE id = ?`,
        )
        .run(
          input.status,
          JSON.stringify(result),
          input.status === 'dismissed' ? (input.reason ?? null) : null,
          input.artifactId ?? null,
          now,
          input.id,
        );
      this.db
        .prepare(
          `INSERT INTO hypothesis_events
           (id, hypothesis_id, status, validation_result_json, reason, artifact_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          randomUUID(),
          input.id,
          input.status,
          JSON.stringify(result),
          input.reason ?? null,
          input.artifactId ?? null,
          now,
        );
    })();
    return this.findById(input.id)!;
  }
}
