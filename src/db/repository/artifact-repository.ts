import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import type Database from 'better-sqlite3';
import type { Artifact } from '../../types/domain.js';

export interface ArtifactRepositoryOptions {
  rootDir?: string;
}

interface ArtifactRow {
  id: string;
  action_id: string;
  path: string;
}

function fromRow(row: ArtifactRow): Artifact {
  return { id: row.id, actionId: row.action_id, path: row.path };
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

  create(input: { actionId: string; path: string }): Artifact {
    const path = this.requireRelativePath(input.path);
    const resolved = this.resolvePath(path);
    if (!existsSync(resolved) || !statSync(resolved).isFile()) {
      throw new Error(`Artifact file not found: ${path}`);
    }
    this.requireInsideRoot(realpathSync(resolved));
    const id = randomUUID();
    this.db
      .prepare('INSERT INTO artifacts (id, action_id, path) VALUES (?, ?, ?)')
      .run(id, input.actionId, path);
    return this.findById(id)!;
  }

  findById(id: string): Artifact | undefined {
    const row = this.db.prepare('SELECT * FROM artifacts WHERE id = ?').get(id) as
      | ArtifactRow
      | undefined;
    return row === undefined ? undefined : fromRow(row);
  }

  listByAction(actionId: string): Artifact[] {
    return (
      this.db
        .prepare('SELECT * FROM artifacts WHERE action_id = ? ORDER BY path')
        .all(actionId) as ArtifactRow[]
    ).map(fromRow);
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
