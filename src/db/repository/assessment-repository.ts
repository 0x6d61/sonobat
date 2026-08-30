import { randomUUID } from 'node:crypto';
import type Database from 'better-sqlite3';
import type { Assessment, CreateAssessmentInput } from '../../types/assessment.js';

interface AssessmentRow {
  id: string;
  name: string;
  created_at: string;
  updated_at: string;
}

function fromRow(row: AssessmentRow): Assessment {
  return {
    id: row.id,
    name: row.name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class AssessmentRepository {
  constructor(private readonly db: Database.Database) {}

  create(input: CreateAssessmentInput): Assessment {
    if (input.name.trim() === '') throw new Error('name must not be empty');
    const id = randomUUID();
    const now = new Date().toISOString();
    this.db
      .prepare('INSERT INTO assessments (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)')
      .run(id, input.name, now, now);
    return this.findById(id)!;
  }

  findById(id: string): Assessment | undefined {
    const row = this.db.prepare('SELECT * FROM assessments WHERE id = ?').get(id) as
      | AssessmentRow
      | undefined;
    return row === undefined ? undefined : fromRow(row);
  }

  list(): Assessment[] {
    return (
      this.db.prepare('SELECT * FROM assessments ORDER BY created_at, id').all() as AssessmentRow[]
    ).map(fromRow);
  }
}
