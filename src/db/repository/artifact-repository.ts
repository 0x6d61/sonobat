import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import type Database from 'better-sqlite3';
import type { Artifact } from '../../types/domain.js';
import { resolveAssessmentId } from './assessment-scope.js';

export interface ArtifactRepositoryOptions {
  rootDir?: string;
}

interface ArtifactRow {
  id: string;
  assessment_id: string;
  activity_id: string | null;
  path: string;
  media_type: string | null;
  sha256: string | null;
  captured_at: string;
  created_at: string;
}

function fromRow(row: ArtifactRow): Artifact {
  return {
    id: row.id,
    assessmentId: row.assessment_id,
    ...(row.activity_id === null ? {} : { activityId: row.activity_id }),
    path: row.path,
    ...(row.media_type === null ? {} : { mediaType: row.media_type }),
    ...(row.sha256 === null ? {} : { sha256: row.sha256 }),
    capturedAt: row.captured_at,
    createdAt: row.created_at,
  };
}

export class ArtifactRepository {
  readonly rootDir: string;

  constructor(
    private readonly db: Database.Database,
    options: ArtifactRepositoryOptions = {},
  ) {
    const configured = expandHome(
      options.rootDir ??
        process.env.SONOBAT_ARTIFACT_DIR ??
        resolve(homedir(), '.sonobat', 'artifacts'),
    );
    mkdirSync(configured, { recursive: true, mode: 0o700 });
    this.rootDir = realpathSync(configured);
  }

  create(input: {
    assessmentId?: string;
    activityId?: string;
    path: string;
    mediaType?: string;
    sha256?: string;
    capturedAt?: string;
  }): Artifact {
    const assessmentId = resolveAssessmentId(this.db, input.assessmentId);
    const path = this.requireRelativePath(input.path);
    const resolved = this.resolvePath(path);
    if (!existsSync(resolved) || !statSync(resolved).isFile()) {
      throw new Error(`Artifact file not found: ${path}`);
    }
    this.requireInsideRoot(realpathSync(resolved));
    if (input.activityId !== undefined) {
      const activity = this.db
        .prepare('SELECT id FROM activities WHERE id = ? AND assessment_id = ?')
        .get(input.activityId, assessmentId);
      if (activity === undefined) throw new Error(`Activity not found: ${input.activityId}`);
    }
    const id = randomUUID();
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO artifacts
         (id, assessment_id, activity_id, path, media_type, sha256, captured_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        assessmentId,
        input.activityId ?? null,
        path,
        input.mediaType ?? null,
        input.sha256 ?? null,
        input.capturedAt ?? now,
        now,
      );
    return this.findById(id, assessmentId)!;
  }

  findById(id: string, assessmentId?: string): Artifact | undefined {
    const scope = resolveAssessmentId(this.db, assessmentId);
    const row = this.db
      .prepare('SELECT * FROM artifacts WHERE assessment_id = ? AND id = ?')
      .get(scope, id) as ArtifactRow | undefined;
    return row === undefined ? undefined : fromRow(row);
  }

  list(assessmentId?: string, activityId?: string): Artifact[] {
    const scope = resolveAssessmentId(this.db, assessmentId);
    const rows = (
      activityId === undefined
        ? this.db
            .prepare(
              'SELECT * FROM artifacts WHERE assessment_id = ? ORDER BY captured_at, created_at',
            )
            .all(scope)
        : this.db
            .prepare(
              'SELECT * FROM artifacts WHERE assessment_id = ? AND activity_id = ? ORDER BY captured_at, created_at',
            )
            .all(scope, activityId)
    ) as ArtifactRow[];
    return rows.map(fromRow);
  }

  resolvePath(path: string): string {
    const relativePath = this.requireRelativePath(path);
    const resolved = resolve(this.rootDir, relativePath);
    this.requireInsideRoot(resolved);
    return resolved;
  }

  private requireInsideRoot(resolved: string): void {
    const child = relative(this.rootDir, resolved);
    if (child === '' || child === '..' || child.startsWith(`..${sep}`) || isAbsolute(child)) {
      throw new Error('Artifact path is outside SONOBAT_ARTIFACT_DIR');
    }
  }

  private requireRelativePath(path: string): string {
    if (path.trim() === '' || isAbsolute(path)) throw new Error('Artifact path must be relative');
    return path;
  }
}

function expandHome(path: string): string {
  if (path === '~') return homedir();
  if (path.startsWith(`~${sep}`)) return resolve(homedir(), path.slice(2));
  return path;
}
