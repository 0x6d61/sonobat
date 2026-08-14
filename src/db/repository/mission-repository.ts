import { randomUUID } from 'node:crypto';
import type Database from 'better-sqlite3';

export interface Mission {
  id: string;
  engagementId: string;
  objective: string;
  targets: unknown[];
  successConditions: unknown[];
  stopConditions: unknown[];
  status: string;
  createdAt: string;
  completedAt?: string;
}

interface MissionRow {
  id: string;
  engagement_id: string;
  objective: string;
  targets_json: string;
  success_conditions_json: string;
  stop_conditions_json: string;
  status: string;
  created_at: string;
  completed_at: string | null;
}

function fromRow(row: MissionRow): Mission {
  return {
    id: row.id,
    engagementId: row.engagement_id,
    objective: row.objective,
    targets: JSON.parse(row.targets_json) as unknown[],
    successConditions: JSON.parse(row.success_conditions_json) as unknown[],
    stopConditions: JSON.parse(row.stop_conditions_json) as unknown[],
    status: row.status,
    createdAt: row.created_at,
    ...(row.completed_at === null ? {} : { completedAt: row.completed_at }),
  };
}

export class MissionRepository {
  constructor(private readonly db: Database.Database) {}

  create(input: {
    engagementId: string;
    objective: string;
    targets?: unknown[];
    successConditions?: unknown[];
    stopConditions?: unknown[];
  }): Mission {
    if (input.objective.trim() === '') throw new Error('objective must not be empty');
    const id = randomUUID();
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO missions
         (id, engagement_id, objective, targets_json, success_conditions_json,
          stop_conditions_json, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
      )
      .run(
        id,
        input.engagementId,
        input.objective,
        JSON.stringify(input.targets ?? []),
        JSON.stringify(input.successConditions ?? []),
        JSON.stringify(input.stopConditions ?? []),
        now,
      );
    return this.findById(id)!;
  }

  findById(id: string): Mission | undefined {
    const row = this.db.prepare('SELECT * FROM missions WHERE id = ?').get(id) as
      | MissionRow
      | undefined;
    return row === undefined ? undefined : fromRow(row);
  }

  list(engagementId: string): Mission[] {
    return (
      this.db
        .prepare('SELECT * FROM missions WHERE engagement_id = ? ORDER BY created_at')
        .all(engagementId) as MissionRow[]
    ).map(fromRow);
  }

  complete(id: string): Mission | undefined {
    const now = new Date().toISOString();
    this.db
      .prepare("UPDATE missions SET status = 'completed', completed_at = ? WHERE id = ?")
      .run(now, id);
    return this.findById(id);
  }
}
