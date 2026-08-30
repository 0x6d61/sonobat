import type Database from 'better-sqlite3';

export function resolveAssessmentId(db: Database.Database, assessmentId?: string): string {
  if (assessmentId !== undefined) {
    if (assessmentId.trim() === '') throw new Error('assessmentId must not be empty');
    const row = db.prepare('SELECT id FROM assessments WHERE id = ?').get(assessmentId) as
      | { id: string }
      | undefined;
    if (row === undefined) throw new Error(`Assessment not found: ${assessmentId}`);
    return row.id;
  }

  const assessments = db
    .prepare('SELECT id FROM assessments ORDER BY created_at, id')
    .all() as Array<{ id: string }>;
  if (assessments.length !== 1) {
    throw new Error(
      'assessmentId is required when the database does not have exactly one Assessment',
    );
  }
  return assessments[0].id;
}
