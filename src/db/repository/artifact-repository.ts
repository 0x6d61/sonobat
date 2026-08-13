import type Database from 'better-sqlite3';
import { createHash, randomUUID } from 'node:crypto';
import {
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { Artifact } from '../../types/operational.js';

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;

export interface ArtifactRepositoryOptions {
  rootDir?: string;
  maxBytes?: number;
}

export interface FindArtifactOptions {
  includeSensitive?: boolean;
}

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
  private readonly rootDir: string;
  private readonly maxBytes: number;

  constructor(
    private readonly db: Database.Database,
    options: ArtifactRepositoryOptions = {},
  ) {
    const configuredRoot = resolve(
      options.rootDir ??
        process.env.SONOBAT_ARTIFACT_DIR ??
        join(homedir(), '.sonobat', 'artifacts'),
    );
    mkdirSync(configuredRoot, { recursive: true, mode: 0o700 });
    this.rootDir = realpathSync(configuredRoot);
    this.maxBytes = options.maxBytes ?? parseMaxBytes(process.env.SONOBAT_ARTIFACT_MAX_BYTES);
    if (!Number.isSafeInteger(this.maxBytes) || this.maxBytes <= 0) {
      throw new Error('Artifact maxBytes must be a positive safe integer');
    }
  }

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
    contentBase64?: string;
  }): Artifact {
    if (input.kind.trim() === '' || input.path.trim() === '') {
      throw new Error('Artifact kind and path must not be empty');
    }
    const attrs: unknown = JSON.parse(input.attrsJson ?? '{}');
    if (attrs === null || Array.isArray(attrs) || typeof attrs !== 'object') {
      throw new Error('attrsJson must be a JSON object');
    }
    const id = randomUUID();
    const stored = this.prepareArtifact(id, input.path, input.contentBase64, input.sha256);
    const capturedAt = new Date().toISOString();
    try {
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
          stored.path,
          stored.sha256,
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
    } catch (error) {
      if (stored.created) unlinkSync(stored.path);
      throw error;
    }
    return this.findById(id, { includeSensitive: true })!;
  }

  findById(id: string, options: FindArtifactOptions = {}): Artifact | undefined {
    const row = this.db.prepare('SELECT * FROM artifacts WHERE id = ?').get(id) as
      | ArtifactRow
      | undefined;
    if (row === undefined || (row.sensitivity === 'secret' && !options.includeSensitive)) {
      return undefined;
    }
    return toArtifact(row);
  }

  private prepareArtifact(
    id: string,
    requestedPath: string,
    contentBase64: string | undefined,
    expectedSha256: string | undefined,
  ): { path: string; sha256: string; created: boolean } {
    if (contentBase64 !== undefined) {
      const content = decodeBase64(contentBase64);
      this.requireAllowedSize(content.byteLength);
      const sha256 = digest(content);
      requireMatchingDigest(expectedSha256, sha256);
      const name = basename(requestedPath);
      if (name === '.' || name === sep || name.trim() === '') {
        throw new Error('Artifact path must include a file name');
      }
      const storedPath = join(this.rootDir, id, name);
      mkdirSync(join(this.rootDir, id), { recursive: true });
      writeFileSync(storedPath, content, { flag: 'wx', mode: 0o600 });
      return { path: storedPath, sha256, created: true };
    }

    if (!isAbsolute(requestedPath)) {
      throw new Error('Existing Artifact path must be absolute');
    }
    const storedPath = realpathSync(resolve(requestedPath));
    this.requireInsideRoot(storedPath);
    const stats = statSync(storedPath);
    if (!stats.isFile()) throw new Error('Artifact path must refer to a regular file');
    this.requireAllowedSize(stats.size);
    const sha256 = digest(readFileSync(storedPath));
    requireMatchingDigest(expectedSha256, sha256);
    return { path: storedPath, sha256, created: false };
  }

  private requireInsideRoot(path: string): void {
    const child = relative(this.rootDir, path);
    if (child === '' || child === '..' || child.startsWith(`..${sep}`) || isAbsolute(child)) {
      throw new Error('Artifact path is outside the allowed root');
    }
  }

  private requireAllowedSize(size: number): void {
    if (size > this.maxBytes) {
      throw new Error(`Artifact exceeds the maximum size of ${this.maxBytes} bytes`);
    }
  }
}

function parseMaxBytes(value: string | undefined): number {
  if (value === undefined) return DEFAULT_MAX_BYTES;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error('SONOBAT_ARTIFACT_MAX_BYTES must be a positive safe integer');
  }
  return parsed;
}

function decodeBase64(value: string): Buffer {
  const normalized = value.replace(/\s/g, '');
  if (
    normalized.length === 0 ||
    normalized.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)
  ) {
    throw new Error('contentBase64 must be valid Base64');
  }
  const content = Buffer.from(normalized, 'base64');
  if (content.toString('base64') !== normalized) {
    throw new Error('contentBase64 must be canonical Base64');
  }
  return content;
}

function digest(content: Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

function requireMatchingDigest(expected: string | undefined, actual: string): void {
  if (expected !== undefined && expected.toLowerCase() !== actual) {
    throw new Error('Artifact SHA-256 does not match its content');
  }
}
