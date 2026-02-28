import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import { ScanRepository } from '../../../src/db/repository/scan-repository.js';
import type { Artifact } from '../../../src/types/entities.js';
import type { CreateArtifactInput } from '../../../src/types/repository.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

/** テスト用の ISO 8601 タイムスタンプを返す */
function now(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('ArtifactRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: ArtifactRepository;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    repo = new ArtifactRepository(db);
  });

  it('create - Artifact を作成して返す', () => {
    const input: CreateArtifactInput = {
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/nmap-scan.xml',
      capturedAt: now(),
    };

    const artifact: Artifact = repo.create(input);

    expect(artifact.id).toBeDefined();
    expect(artifact.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(artifact.tool).toBe(input.tool);
    expect(artifact.kind).toBe(input.kind);
    expect(artifact.path).toBe(input.path);
    expect(artifact.capturedAt).toBe(input.capturedAt);
  });

  it('findById - 存在する Artifact を取得する', () => {
    const input: CreateArtifactInput = {
      tool: 'ffuf',
      kind: 'tool_output',
      path: '/tmp/ffuf-result.json',
      capturedAt: now(),
    };

    const created = repo.create(input);
    const found = repo.findById(created.id);

    expect(found).toBeDefined();
    expect(found!.id).toBe(created.id);
    expect(found!.tool).toBe(created.tool);
    expect(found!.kind).toBe(created.kind);
    expect(found!.path).toBe(created.path);
    expect(found!.capturedAt).toBe(created.capturedAt);
  });

  it('findById - 存在しない場合 undefined を返す', () => {
    const found = repo.findById(crypto.randomUUID());

    expect(found).toBeUndefined();
  });

  it('findAll - 全件取得', () => {
    const input1: CreateArtifactInput = {
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/nmap-1.xml',
      capturedAt: now(),
    };
    const input2: CreateArtifactInput = {
      tool: 'ffuf',
      kind: 'tool_output',
      path: '/tmp/ffuf-1.json',
      capturedAt: now(),
    };

    const artifact1 = repo.create(input1);
    const artifact2 = repo.create(input2);

    const all: Artifact[] = repo.findAll();

    expect(all).toHaveLength(2);

    const ids = all.map((a) => a.id);
    expect(ids).toContain(artifact1.id);
    expect(ids).toContain(artifact2.id);
  });

  it('findByTool - tool で絞り込み', () => {
    const nmapInput: CreateArtifactInput = {
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/nmap-scan.xml',
      capturedAt: now(),
    };
    const ffufInput: CreateArtifactInput = {
      tool: 'ffuf',
      kind: 'tool_output',
      path: '/tmp/ffuf-result.json',
      capturedAt: now(),
    };

    const nmapArtifact = repo.create(nmapInput);
    repo.create(ffufInput);

    const nmapResults = repo.findByTool('nmap');

    expect(nmapResults).toHaveLength(1);
    expect(nmapResults[0].id).toBe(nmapArtifact.id);
    expect(nmapResults[0].tool).toBe('nmap');
  });

  it('create - scanId がオプションで紐づけ可能', () => {
    // まず Scan を作成
    const scanRepo = new ScanRepository(db);
    const scan = scanRepo.create({
      startedAt: now(),
    });

    // scanId を指定して Artifact を作成
    const input: CreateArtifactInput = {
      scanId: scan.id,
      tool: 'nmap',
      kind: 'tool_output',
      path: '/tmp/nmap-linked.xml',
      capturedAt: now(),
    };

    const artifact = repo.create(input);

    expect(artifact.scanId).toBe(scan.id);

    // findById でも scanId が取得できること
    const found = repo.findById(artifact.id);
    expect(found).toBeDefined();
    expect(found!.scanId).toBe(scan.id);
  });
});
