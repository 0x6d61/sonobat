import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { migrateDatabase } from '../../src/db/migrate.js';
import { TechniqueDocRepository } from '../../src/db/repository/technique-doc-repository.js';
import { parseMarkdownChunks, extractCategory, indexHacktricks } from '../../src/engine/indexer.js';

// =========================================================
// parseMarkdownChunks
// =========================================================

describe('parseMarkdownChunks', () => {
  it('H1 見出しをタイトルとして抽出する', () => {
    const md = `# Docker Breakout

Some content here about docker.
`;
    const chunks = parseMarkdownChunks(md, 'docker-breakout.md');
    expect(chunks.length).toBeGreaterThanOrEqual(1);
    expect(chunks[0].title).toBe('Docker Breakout');
  });

  it('H2 境界でコンテンツを分割する', () => {
    const md = `# Main Title

Intro paragraph.

## Section One

Content of section one.

## Section Two

Content of section two.
`;
    const chunks = parseMarkdownChunks(md, 'test.md');
    expect(chunks).toHaveLength(3);
    expect(chunks[0].title).toBe('Main Title');
    expect(chunks[0].content).toContain('Intro paragraph');
    expect(chunks[1].content).toContain('Section One');
    expect(chunks[1].content).toContain('Content of section one');
    expect(chunks[2].content).toContain('Section Two');
    expect(chunks[2].content).toContain('Content of section two');
  });

  it('H1 がない場合はファイル名をタイトルにする', () => {
    const md = `Just some content without headings.`;
    const chunks = parseMarkdownChunks(md, 'no-heading.md');
    expect(chunks).toHaveLength(1);
    expect(chunks[0].title).toBe('no-heading');
  });

  it('H2 がない場合は全文を 1 チャンクにする', () => {
    const md = `# Single Section

All content in one section without H2 headings.
More content here.
`;
    const chunks = parseMarkdownChunks(md, 'test.md');
    expect(chunks).toHaveLength(1);
    expect(chunks[0].content).toContain('All content in one section');
  });

  it('空ファイルは空配列を返す', () => {
    const chunks = parseMarkdownChunks('', 'empty.md');
    expect(chunks).toHaveLength(0);
  });

  it('空白のみのファイルは空配列を返す', () => {
    const chunks = parseMarkdownChunks('   \n\n  ', 'whitespace.md');
    expect(chunks).toHaveLength(0);
  });

  it('チャンクインデックスが 0 始まりで連番', () => {
    const md = `# Title

Intro.

## A

Content A.

## B

Content B.
`;
    const chunks = parseMarkdownChunks(md, 'test.md');
    expect(chunks[0].chunkIndex).toBe(0);
    expect(chunks[1].chunkIndex).toBe(1);
    expect(chunks[2].chunkIndex).toBe(2);
  });
});

// =========================================================
// extractCategory
// =========================================================

describe('extractCategory', () => {
  it('ディレクトリ構造からカテゴリを抽出する', () => {
    expect(extractCategory('linux-hardening/privilege-escalation/docker-breakout.md')).toBe(
      'linux-hardening/privilege-escalation',
    );
  });

  it('ルート直下のファイルはカテゴリが空文字', () => {
    expect(extractCategory('README.md')).toBe('');
  });

  it('1 階層のディレクトリ', () => {
    expect(extractCategory('web/sql-injection.md')).toBe('web');
  });

  it('Windows パスも正しく処理する', () => {
    // path.posix.join で正規化されるので / 区切り前提
    expect(extractCategory('windows-hardening\\active-directory\\kerberoasting.md')).toBe(
      'windows-hardening/active-directory',
    );
  });
});

// =========================================================
// indexHacktricks
// =========================================================

describe('indexHacktricks', () => {
  let db: InstanceType<typeof Database>;
  let repo: TechniqueDocRepository;
  let tmpDir: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    repo = new TechniqueDocRepository(db);

    // テスト用の一時ディレクトリに Markdown ファイルを作成
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'indexer-test-'));
    fs.mkdirSync(path.join(tmpDir, 'linux-hardening'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'web'), { recursive: true });

    fs.writeFileSync(
      path.join(tmpDir, 'linux-hardening', 'docker-breakout.md'),
      `# Docker Breakout

Intro to docker breakout.

## Container Escape

Escape using nsenter and host PID namespace.

## Capabilities

Abusing Linux capabilities for breakout.
`,
    );

    fs.writeFileSync(
      path.join(tmpDir, 'web', 'sql-injection.md'),
      `# SQL Injection

UNION-based and blind SQL injection techniques.
`,
    );

    // README はスキップされるべき
    fs.writeFileSync(path.join(tmpDir, 'README.md'), '# HackTricks\nMain README.');
  });

  it('ディレクトリを再帰的にインデックスできる', () => {
    const count = indexHacktricks(db, tmpDir);
    expect(count).toBeGreaterThanOrEqual(4); // docker-breakout: 3 chunks + sql-injection: 1 chunk
  });

  it('README.md はスキップされる', () => {
    indexHacktricks(db, tmpDir);
    const docs = repo.search('HackTricks Main README');
    expect(docs).toHaveLength(0);
  });

  it('再インデックス時に古いデータが削除される', () => {
    indexHacktricks(db, tmpDir);
    const count1 = repo.count();

    // 2回目のインデックス
    indexHacktricks(db, tmpDir);
    const count2 = repo.count();

    expect(count2).toBe(count1);
  });

  it('カテゴリが正しく設定される', () => {
    indexHacktricks(db, tmpDir);
    const categories = repo.listCategories();
    expect(categories).toContain('linux-hardening');
    expect(categories).toContain('web');
  });

  it('FTS5 検索で結果を返せる', () => {
    indexHacktricks(db, tmpDir);
    const results = repo.search('sql injection');
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].title).toBe('SQL Injection');
  });
});
