import type Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';
import type { CreateMissionInput, Mission } from '../../types/operational.js';

interface MissionRow {
  id: string;
  engagement_id: string;
  run_id: string | null;
  objective: string;
  targets_json: string;
  success_conditions_json: string;
  stop_conditions_json: string;
  status: string;
  created_at: string;
  completed_at: string | null;
}

function parseJsonArray(value: string, field: string): string {
  const parsed: unknown = JSON.parse(value);
  if (!Array.isArray(parsed)) throw new Error(`${field} must be a JSON array`);
  return JSON.stringify(parsed);
}

function toMission(row: MissionRow): Mission {
  return {
    id: row.id,
    engagementId: row.engagement_id,
    ...(row.run_id === null ? {} : { runId: row.run_id }),
    objective: row.objective,
    targetsJson: row.targets_json,
    successConditionsJson: row.success_conditions_json,
    stopConditionsJson: row.stop_conditions_json,
    status: row.status,
    createdAt: row.created_at,
    ...(row.completed_at === null ? {} : { completedAt: row.completed_at }),
  };
}

export class MissionRepository {
  constructor(private readonly db: Database.Database) {}

  create(input: CreateMissionInput): Mission {
    if (input.objective.trim() === '') throw new Error('objective must not be empty');
    const id = randomUUID();
    const createdAt = new Date().toISOString();
    const targetsJson = parseJsonArray(input.targetsJson ?? '[]', 'targetsJson');
    const successJson = parseJsonArray(
      input.successConditionsJson ?? '[]',
      'successConditionsJson',
    );
    const stopJson = parseJsonArray(input.stopConditionsJson ?? '[]', 'stopConditionsJson');
    this.db
      .prepare(
        `INSERT INTO missions
         (id, engagement_id, run_id, objective, targets_json, success_conditions_json,
          stop_conditions_json, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.engagementId,
        input.runId ?? null,
        input.objective,
        targetsJson,
        successJson,
        stopJson,
        input.status ?? 'active',
        createdAt,
      );
    return this.findById(id)!;
  }

  findById(id: string): Mission | undefined {
    const row = this.db.prepare('SELECT * FROM missions WHERE id = ?').get(id) as
      | MissionRow
      | undefined;
    return row === undefined ? undefined : toMission(row);
  }

  findByEngagement(engagementId: string): Mission[] {
    const rows = this.db
      .prepare('SELECT * FROM missions WHERE engagement_id = ? ORDER BY created_at DESC')
      .all(engagementId) as MissionRow[];
    return rows.map(toMission);
  }

  complete(id: string): Mission | undefined {
    const completedAt = new Date().toISOString();
    this.db
      .prepare("UPDATE missions SET status = 'completed', completed_at = ? WHERE id = ?")
      .run(completedAt, id);
    return this.findById(id);
  }
}
