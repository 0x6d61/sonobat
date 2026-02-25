/**
 * sonobat — Engine layer type definitions
 *
 * Engine 層の入出力型。MCP / CLI / GraphQL 全てから再利用可能。
 */

import type { NormalizeResult } from '../engine/normalizer.js';

// ============================================================
// Ingest
// ============================================================

/** ingest() の入力。ファイルパスとツール種別を指定する。 */
export interface IngestInput {
  path: string;
  tool: 'nmap' | 'ffuf' | 'nuclei';
}

/** ingest() の戻り値。作成された Artifact ID と正規化結果を返す。 */
export interface IngestResult {
  artifactId: string;
  normalizeResult: NormalizeResult;
}

// ============================================================
// Propose
// ============================================================

/** Proposer が返す単一のアクション提案。 */
export interface Action {
  /** アクション種別 */
  kind:
    | 'nmap_scan'
    | 'ffuf_discovery'
    | 'nuclei_scan'
    | 'parameter_discovery'
    | 'value_collection'
    | 'vhost_discovery';
  /** 人間向けの説明 */
  description: string;
  /** 実行可能なコマンド例（ない場合は undefined） */
  command?: string;
  /** 対象エンティティの参照情報 */
  params: Record<string, unknown>;
}
