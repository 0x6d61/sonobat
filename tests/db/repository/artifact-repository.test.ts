import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import { EngagementRepository } from '../../../src/db/repository/engagement-repository.js';
import { ActionQueueRepository } from '../../../src/db/repository/action-queue-repository.js';
import { ActionExecutionRepository } from '../../../src/db/repository/action-execution-repository.js';

describe('ArtifactRepository', () => {
  let db: InstanceType<typeof Database>;
  let rootDir: string;
  let input: {
    engagementId: string;
    actionId: string;
    actionExecutionId: string;
    producer: string;
    kind: string;
    path: string;
  };

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    rootDir = mkdtempSync(join(tmpdir(), 'sonobat-artifact-test-'));
    const engagement = new EngagementRepository(db).create({ name: 'test' });
    const action = new ActionQueueRepository(db).enqueue({
      engagementId: engagement.id,
      kind: 'test',
      dedupeKey: 'artifact-test',
    });
    const execution = new ActionExecutionRepository(db).create({
      actionId: action.id,
      executor: 'worker-1',
    });
    input = {
      engagementId: engagement.id,
      actionId: action.id,
      actionExecutionId: execution.id,
      producer: 'worker-1',
      kind: 'stdout',
      path: 'stdout.txt',
    };
  });

  afterEach(() => {
    db.close();
    rmSync(rootDir, { recursive: true, force: true });
  });

  it('Base64内容を管理領域へ保存しSHA-256を記録する', () => {
    const content = Buffer.from('hello artifact');
    const repo = new ArtifactRepository(db, { rootDir });

    const artifact = repo.create({ ...input, contentBase64: content.toString('base64') });

    expect(readFileSync(artifact.path)).toEqual(content);
    expect(artifact.sha256).toBe(createHash('sha256').update(content).digest('hex'));
  });

  it('管理領域外の既存ファイルを拒否する', () => {
    const outside = join(tmpdir(), `sonobat-outside-${crypto.randomUUID()}.txt`);
    writeFileSync(outside, 'outside');
    const repo = new ArtifactRepository(db, { rootDir });
    try {
      expect(() => repo.create({ ...input, path: outside })).toThrow(/outside the allowed root/);
    } finally {
      rmSync(outside, { force: true });
    }
  });

  it('管理領域外を指すシンボリックリンクを拒否する', () => {
    const outside = join(tmpdir(), `sonobat-outside-${crypto.randomUUID()}.txt`);
    const link = join(rootDir, 'outside-link.txt');
    writeFileSync(outside, 'outside');
    symlinkSync(outside, link);
    const repo = new ArtifactRepository(db, { rootDir });
    try {
      expect(() => repo.create({ ...input, path: link })).toThrow(/outside the allowed root/);
    } finally {
      rmSync(outside, { force: true });
    }
  });

  it('上限を超える内容と一致しないSHA-256を拒否する', () => {
    const repo = new ArtifactRepository(db, { rootDir, maxBytes: 3 });
    expect(() =>
      repo.create({ ...input, contentBase64: Buffer.from('four').toString('base64') }),
    ).toThrow(/maximum size/);

    expect(() =>
      new ArtifactRepository(db, { rootDir }).create({
        ...input,
        contentBase64: Buffer.from('data').toString('base64'),
        sha256: '0'.repeat(64),
      }),
    ).toThrow(/does not match/);
  });

  it('管理領域内の既存ファイルを検証して登録する', () => {
    const directory = join(rootDir, 'existing');
    mkdirSync(directory);
    const path = join(directory, 'result.json');
    writeFileSync(path, '{"ok":true}', { mode: 0o600 });

    const artifact = new ArtifactRepository(db, { rootDir }).create({ ...input, path });

    expect(artifact.path).toBe(path);
    expect(artifact.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it('secretは明示的に許可した取得だけに返す', () => {
    const repo = new ArtifactRepository(db, { rootDir });
    const artifact = repo.create({
      ...input,
      sensitivity: 'secret',
      contentBase64: Buffer.from('secret').toString('base64'),
    });

    expect(repo.findById(artifact.id)).toBeUndefined();
    expect(repo.findById(artifact.id, { includeSensitive: true })?.id).toBe(artifact.id);
  });
});
