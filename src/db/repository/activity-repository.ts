import { randomUUID } from 'node:crypto';
import type Database from 'better-sqlite3';
import type { Activity, RecordActivityInput } from '../../types/activity.js';

interface ActivityRow {
  id: string;
  assessment_id: string;
  kind: string;
  command: string | null;
  description: string;
  target: string | null;
  status: Activity['status'];
  started_at: string;
  finished_at: string | null;
  result_summary: string | null;
  error_summary: string | null;
  created_at: string;
}

function fromRow(row: ActivityRow): Activity {
  return {
    id: row.id,
    assessmentId: row.assessment_id,
    kind: row.kind,
    ...(row.command === null ? {} : { command: row.command }),
    description: row.description,
    ...(row.target === null ? {} : { target: row.target }),
    status: row.status,
    startedAt: row.started_at,
    ...(row.finished_at === null ? {} : { finishedAt: row.finished_at }),
    ...(row.result_summary === null ? {} : { resultSummary: row.result_summary }),
    ...(row.error_summary === null ? {} : { errorSummary: row.error_summary }),
    createdAt: row.created_at,
  };
}

export class ActivityRepository {
  constructor(private readonly db: Database.Database) {}

  record(input: RecordActivityInput): Activity {
    if (input.kind.trim() === '') throw new Error('kind must not be empty');
    if (input.command !== undefined && input.command.trim() === '') {
      throw new Error('command must not be empty');
    }
    if (input.description.trim() === '') throw new Error('description must not be empty');
    if (input.target !== undefined && input.target.trim() === '') {
      throw new Error('target must not be empty');
    }
    if (input.finishedAt !== undefined && input.status === 'started') {
      throw new Error('started Activity must not have finishedAt');
    }

    const assessment = this.db
      .prepare('SELECT id FROM assessments WHERE id = ?')
      .get(input.assessmentId) as { id: string } | undefined;
    if (assessment === undefined) {
      throw new Error(`Assessment not found: ${input.assessmentId}`);
    }

    const now = new Date().toISOString();
    const status = input.status ?? 'completed';
    const startedAt = input.startedAt ?? now;
    const finishedAt = input.finishedAt ?? (status === 'started' ? undefined : now);
    const id = randomUUID();

    this.db
      .prepare(
        `INSERT INTO activities
         (id, assessment_id, kind, command, description, target, status, started_at,
          finished_at, result_summary, error_summary, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.assessmentId,
        input.kind,
        input.command ?? null,
        input.description,
        input.target ?? null,
        status,
        startedAt,
        finishedAt ?? null,
        input.resultSummary ?? null,
        input.errorSummary ?? null,
        now,
      );

    return this.findById(input.assessmentId, id)!;
  }

  findById(assessmentId: string, id: string): Activity | undefined {
    const row = this.db
      .prepare('SELECT * FROM activities WHERE assessment_id = ? AND id = ?')
      .get(assessmentId, id) as ActivityRow | undefined;
    return row === undefined ? undefined : fromRow(row);
  }

  list(assessmentId: string): Activity[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM activities
         WHERE assessment_id = ? ORDER BY started_at, created_at`,
      )
      .all(assessmentId) as ActivityRow[];
    return rows.map(fromRow);
  }
}
