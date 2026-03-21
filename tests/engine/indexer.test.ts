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
// indexHacktricks — 基本動作
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
    const result = indexHacktricks(db, tmpDir);
    expect(result.totalChunks).toBeGreaterThanOrEqual(4); // docker-breakout: 3 chunks + sql-injection: 1 chunk
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

  // =========================================================
  // IndexResult の構造
  // =========================================================

  it('IndexResult を返す', () => {
    const result = indexHacktricks(db, tmpDir);
    expect(result).toHaveProperty('totalChunks');
    expect(result).toHaveProperty('newFiles');
    expect(result).toHaveProperty('updatedFiles');
    expect(result).toHaveProperty('deletedFiles');
    expect(result).toHaveProperty('skippedFiles');
    expect(typeof result.totalChunks).toBe('number');
  });
});

// =========================================================
// 増分インデックス
// =========================================================

describe('indexHacktricks — 増分インデックス', () => {
  let db: InstanceType<typeof Database>;
  let repo: TechniqueDocRepository;
  let tmpDir: string;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    repo = new TechniqueDocRepository(db);

    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'indexer-incr-test-'));
    fs.mkdirSync(path.join(tmpDir, 'web'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'linux'), { recursive: true });
  });

  it('初回は全ファイルが新規としてカウントされる', () => {
    fs.writeFileSync(path.join(tmpDir, 'web', 'sqli.md'), '# SQLi\n\nContent about SQL injection.');
    fs.writeFileSync(path.join(tmpDir, 'linux', 'docker.md'), '# Docker\n\nDocker content.');

    const result = indexHacktricks(db, tmpDir);
    expect(result.newFiles).toBe(2);
    expect(result.updatedFiles).toBe(0);
    expect(result.deletedFiles).toBe(0);
    expect(result.skippedFiles).toBe(0);
    expect(result.totalChunks).toBeGreaterThan(0);
  });

  it('変更なしの場合はスキップされる', () => {
    fs.writeFileSync(path.join(tmpDir, 'web', 'sqli.md'), '# SQLi\n\nContent about SQL injection.');

    const result1 = indexHacktricks(db, tmpDir);
    expect(result1.newFiles).toBe(1);

    // 2回目は変更なし → スキップ
    const result2 = indexHacktricks(db, tmpDir);
    expect(result2.skippedFiles).toBe(1);
    expect(result2.newFiles).toBe(0);
    expect(result2.updatedFiles).toBe(0);
    expect(result2.deletedFiles).toBe(0);
    expect(repo.count()).toBe(result1.totalChunks);
  });

  it('ファイルが追加された場合は新規としてインデックスされる', () => {
    fs.writeFileSync(path.join(tmpDir, 'web', 'sqli.md'), '# SQLi\n\nSQL injection.');

    indexHacktricks(db, tmpDir);
    const countBefore = repo.count();

    // 新しいファイルを追加
    fs.writeFileSync(path.join(tmpDir, 'web', 'xss.md'), '# XSS\n\nCross-site scripting.');

    const result2 = indexHacktricks(db, tmpDir);
    expect(result2.newFiles).toBe(1);
    expect(result2.skippedFiles).toBe(1);
    // 既存チャンク + 新規チャンクが DB に存在する
    expect(repo.count()).toBe(countBefore + result2.totalChunks);
  });

  it('ファイルが削除された場合は DB からも削除される', () => {
    fs.writeFileSync(path.join(tmpDir, 'web', 'sqli.md'), '# SQLi\n\nSQL injection.');
    fs.writeFileSync(path.join(tmpDir, 'web', 'xss.md'), '# XSS\n\nCross-site scripting.');

    indexHacktricks(db, tmpDir);
    expect(repo.count()).toBeGreaterThanOrEqual(2);

    // ファイルを削除
    fs.unlinkSync(path.join(tmpDir, 'web', 'xss.md'));

    const result2 = indexHacktricks(db, tmpDir);
    expect(result2.deletedFiles).toBe(1);
    expect(result2.skippedFiles).toBe(1);

    // XSS のドキュメントが DB から消えていること
    const xssResults = repo.search('cross-site scripting');
    expect(xssResults).toHaveLength(0);
  });

  it('ファイルが更新（mtime変更）された場合は再インデックスされる', () => {
    fs.writeFileSync(path.join(tmpDir, 'web', 'sqli.md'), '# SQLi\n\nSQL injection basics.');

    indexHacktricks(db, tmpDir);

    // ファイルの内容を変更（mtimeも変わる）
    // 少し待ってから書き込むことで mtime を確実に変える
    const filePath = path.join(tmpDir, 'web', 'sqli.md');
    const futureTime = new Date(Date.now() + 2000);
    fs.writeFileSync(
      filePath,
      '# SQLi\n\nAdvanced SQL injection techniques.\n\n## UNION Attack\n\nUNION-based injection.',
    );
    fs.utimesSync(filePath, futureTime, futureTime);

    const result2 = indexHacktricks(db, tmpDir);
    expect(result2.updatedFiles).toBe(1);
    expect(result2.newFiles).toBe(0);
    expect(result2.deletedFiles).toBe(0);
    expect(result2.skippedFiles).toBe(0);

    // 新しい内容が検索できること
    const results = repo.search('UNION injection');
    expect(results.length).toBeGreaterThanOrEqual(1);
  });

  it('file_mtime が DB に保存される', () => {
    fs.writeFileSync(path.join(tmpDir, 'web', 'sqli.md'), '# SQLi\n\nContent.');

    indexHacktricks(db, tmpDir);

    const mtimes = repo.findMtimesBySource('hacktricks');
    expect(mtimes.size).toBe(1);
    expect(mtimes.get('web/sqli.md')).toBeDefined();
    expect(mtimes.get('web/sqli.md')).not.toBeNull();
  });
});
