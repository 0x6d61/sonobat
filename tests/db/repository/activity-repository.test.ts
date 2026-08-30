import { describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { ActivityRepository } from '../../../src/db/repository/activity-repository.js';
import { AssessmentRepository } from '../../../src/db/repository/assessment-repository.js';

describe('ActivityRepository', () => {
  it('records and lists Activity history within one Assessment', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const assessments = new AssessmentRepository(db);
    const first = assessments.create({ name: 'first' });
    const second = assessments.create({ name: 'second' });
    const activities = new ActivityRepository(db);

    const completed = activities.record({
      assessmentId: first.id,
      kind: 'nmap',
      command: 'nmap -sV 10.10.10.5',
      description: 'nmap -sV target',
      target: 'host:target',
      status: 'completed',
      resultSummary: '22/tcp and 80/tcp are open',
    });
    activities.record({
      assessmentId: second.id,
      kind: 'curl',
      description: 'GET /admin',
      status: 'failed',
      errorSummary: 'HTTP 403',
    });

    expect(activities.findById(first.id, completed.id)).toEqual(completed);
    expect(completed.command).toBe('nmap -sV 10.10.10.5');
    expect(activities.list(first.id)).toEqual([completed]);
    expect(activities.list(second.id)).toHaveLength(1);
    expect(activities.findById(second.id, completed.id)).toBeUndefined();
    db.close();
  });

  it('keeps a started Activity append-only', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const assessment = new AssessmentRepository(db).create({ name: 'test' });
    const activities = new ActivityRepository(db);

    const started = activities.record({
      assessmentId: assessment.id,
      kind: 'http',
      description: 'GET /',
      status: 'started',
    });

    expect(started.status).toBe('started');
    expect(started.finishedAt).toBeUndefined();
    expect(activities.list(assessment.id)).toEqual([started]);
    db.close();
  });

  it('rejects empty fields and unknown Assessments', () => {
    const db = new Database(':memory:');
    migrateDatabase(db);
    const activities = new ActivityRepository(db);

    expect(() =>
      activities.record({
        assessmentId: 'missing',
        kind: 'scan',
        description: 'nmap',
        status: 'completed',
      }),
    ).toThrow(/Assessment/);
    expect(() =>
      activities.record({
        assessmentId: 'missing',
        kind: ' ',
        description: 'nmap',
        status: 'completed',
      }),
    ).toThrow(/kind/);
    expect(() =>
      activities.record({
        assessmentId: 'missing',
        kind: 'scan',
        command: ' ',
        description: 'nmap',
        status: 'completed',
      }),
    ).toThrow(/command/);
    db.close();
  });
});
