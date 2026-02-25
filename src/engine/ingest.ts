/**
 * sonobat — Ingest Engine
 *
 * ツール出力ファイルを読み込み、パース・正規化してDBに格納する。
 * ingestContent() はコアロジック（ファイルシステム非依存・テスト可能）。
 * ingest() はファイル読み込みの薄いラッパー。
 */

import type Database from 'better-sqlite3';
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import type { IngestInput, IngestResult } from '../types/engine.js';
import { ArtifactRepository } from '../db/repository/artifact-repository.js';
import { parseNmapXml } from '../parser/nmap-parser.js';
import { parseFfufJson } from '../parser/ffuf-parser.js';
import { parseNucleiJsonl } from '../parser/nuclei-parser.js';
import { normalize } from './normalizer.js';

/**
 * ツール出力の文字列を直接受け取り、パース・正規化してDBに格納する。
 * ファイルシステムに依存しないため、テストから直接呼び出せる。
 *
 * @param db       better-sqlite3 の Database インスタンス
 * @param tool     ツール種別（'nmap' | 'ffuf' | 'nuclei'）
 * @param content  ツール出力の文字列
 * @param filePath Artifact に記録するファイルパス
 * @returns IngestResult（artifactId + normalizeResult）
 */
export function ingestContent(
  db: Database.Database,
  tool: 'nmap' | 'ffuf' | 'nuclei',
  content: string,
  filePath: string,
): IngestResult {
  // 1. SHA-256 ハッシュを計算
  const sha256 = crypto.createHash('sha256').update(content).digest('hex');

  // 2. Artifact を作成
  const artifactRepo = new ArtifactRepository(db);
  const artifact = artifactRepo.create({
    tool,
    kind: 'tool_output',
    path: filePath,
    sha256,
    capturedAt: new Date().toISOString(),
  });

  // 3. ツール種別に応じてパース
  let parseResult;
  switch (tool) {
    case 'nmap':
      parseResult = parseNmapXml(content);
      break;
    case 'ffuf':
      parseResult = parseFfufJson(content);
      break;
    case 'nuclei':
      parseResult = parseNucleiJsonl(content);
      break;
    default: {
      // never 型による網羅性チェック — 未知の tool が渡された場合はコンパイルエラー
      const _exhaustive: never = tool;
      throw new Error(`Unknown tool: ${String(_exhaustive)}`);
    }
  }

  // 4. 正規化してDBに書き込む
  const normalizeResult = normalize(db, artifact.id, parseResult);

  // 5. 結果を返す
  return {
    artifactId: artifact.id,
    normalizeResult,
  };
}

/**
 * ファイルパスからツール出力を読み込み、インジェストする。
 * ingestContent() の薄いラッパー。
 *
 * @param db    better-sqlite3 の Database インスタンス
 * @param input IngestInput（path + tool）
 * @returns IngestResult
 */
export function ingest(db: Database.Database, input: IngestInput): IngestResult {
  const resolved = path.resolve(input.path);
  const content = fs.readFileSync(resolved, 'utf-8');
  return ingestContent(db, input.tool, content, resolved);
}
