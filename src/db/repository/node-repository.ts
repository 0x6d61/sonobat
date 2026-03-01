/**
 * sonobat — NodeRepository
 *
 * Graph-native スキーマの nodes テーブルに対する CRUD 操作を提供する。
 * snake_case (DB) ↔ camelCase (TypeScript) の変換を内部で行う。
 */

import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { GraphNode, NodeKind } from '../../types/graph.js';
import { validateProps, buildNaturalKey } from '../../types/graph.js';

// ---------------------------------------------------------------------------
// DB row 型
// ---------------------------------------------------------------------------

/** better-sqlite3 から返る nodes テーブルの行形状 */
interface NodeRow {
  id: string;
  kind: string;
  natural_key: string;
  props_json: string;
  evidence_artifact_id: string | null;
  created_at: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Row → GraphNode 変換
// ---------------------------------------------------------------------------

/** snake_case DB row を camelCase GraphNode にマッピング */
function rowToGraphNode(row: NodeRow): GraphNode {
  return {
    id: row.id,
    kind: row.kind as NodeKind,
    naturalKey: row.natural_key,
    propsJson: row.props_json,
    ...(row.evidence_artifact_id !== null ? { evidenceArtifactId: row.evidence_artifact_id } : {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// ---------------------------------------------------------------------------
// NodeRepository
// ---------------------------------------------------------------------------

/**
 * nodes テーブルの CRUD リポジトリ。
 *
 * - props は Zod バリデーション後に JSON 文字列としてストア
 * - natural_key は buildNaturalKey() で自動生成
 * - ID は crypto.randomUUID() で生成
 */
export class NodeRepository {
  private readonly db: Database.Database;

  private readonly insertStmt: Database.Statement;
  private readonly selectByIdStmt: Database.Statement;
  private readonly selectByKindStmt: Database.Statement;
  private readonly selectByNaturalKeyStmt: Database.Statement;
  private readonly updatePropsStmt: Database.Statement;
  private readonly deleteStmt: Database.Statement;

  constructor(db: Database.Database) {
    this.db = db;

    this.insertStmt = this.db.prepare(
      `INSERT INTO nodes (id, kind, natural_key, props_json, evidence_artifact_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );

    this.selectByIdStmt = this.db.prepare(
      `SELECT id, kind, natural_key, props_json, evidence_artifact_id, created_at, updated_at
       FROM nodes WHERE id = ?`,
    );

    this.selectByKindStmt = this.db.prepare(
      `SELECT id, kind, natural_key, props_json, evidence_artifact_id, created_at, updated_at
       FROM nodes WHERE kind = ?`,
    );

    this.selectByNaturalKeyStmt = this.db.prepare(
      `SELECT id, kind, natural_key, props_json, evidence_artifact_id, created_at, updated_at
       FROM nodes WHERE natural_key = ?`,
    );

    this.updatePropsStmt = this.db.prepare(
      `UPDATE nodes SET props_json = ?, updated_at = ? WHERE id = ?`,
    );

    this.deleteStmt = this.db.prepare(`DELETE FROM nodes WHERE id = ?`);
  }

  /**
   * ノードを新規作成して返す。
   *
   * @param kind              ノード種別
   * @param props             ノードの props（Zod バリデーション対象）
   * @param evidenceArtifactId  証拠 artifact の ID（任意）
   * @param parentId          親ノード ID（service, endpoint 等で必要）
   * @throws props バリデーションエラー、または natural_key 重複時
   */
  create(
    kind: NodeKind,
    props: Record<string, unknown>,
    evidenceArtifactId?: string,
    parentId?: string,
  ): GraphNode {
    // props バリデーション
    const validation = validateProps(kind, props);
    if (!validation.ok) {
      throw new Error(`Props validation failed for kind="${kind}": ${validation.error}`);
    }

    const id = crypto.randomUUID();
    const naturalKey = buildNaturalKey(kind, validation.data, parentId);
    const propsJson = JSON.stringify(validation.data);
    const timestamp = new Date().toISOString();

    this.insertStmt.run(
      id,
      kind,
      naturalKey,
      propsJson,
      evidenceArtifactId ?? null,
      timestamp,
      timestamp,
    );

    return {
      id,
      kind,
      naturalKey,
      propsJson,
      ...(evidenceArtifactId !== undefined ? { evidenceArtifactId } : {}),
      createdAt: timestamp,
      updatedAt: timestamp,
    };
  }

  /**
   * Upsert: natural_key が存在すれば更新、なければ新規作成。
   *
   * UUID ベースの natural key (observation, credential, vulnerability, svc_observation) は
   * 毎回異なるキーが生成されるため、常に新規作成となる。
   *
   * @returns { node, created } — created は新規作成時 true、既存更新時 false
   */
  upsert(
    kind: NodeKind,
    props: Record<string, unknown>,
    evidenceArtifactId?: string,
    parentId?: string,
  ): { node: GraphNode; created: boolean } {
    // props バリデーション
    const validation = validateProps(kind, props);
    if (!validation.ok) {
      throw new Error(`Props validation failed for kind="${kind}": ${validation.error}`);
    }

    const naturalKey = buildNaturalKey(kind, validation.data, parentId);

    // 既存ノードを natural_key で検索
    const existing = this.findByNaturalKey(naturalKey);

    if (existing !== undefined) {
      // 既存ノードの props を更新
      const propsJson = JSON.stringify(validation.data);
      const timestamp = new Date().toISOString();
      this.updatePropsStmt.run(propsJson, timestamp, existing.id);

      const updated = this.findById(existing.id)!;
      return { node: updated, created: false };
    }

    // 新規作成
    const node = this.create(kind, props, evidenceArtifactId, parentId);
    return { node, created: true };
  }

  /**
   * ID でノードを取得する。存在しなければ undefined。
   */
  findById(id: string): GraphNode | undefined {
    const row = this.selectByIdStmt.get(id) as NodeRow | undefined;
    if (row === undefined) {
      return undefined;
    }
    return rowToGraphNode(row);
  }

  /**
   * kind でノード一覧を取得する。
   *
   * filters を指定すると、props_json の中身に対して JSON_EXTRACT で絞り込む。
   * 例: findByKind('host', { authority: '192.168.1.1' })
   *     → WHERE kind = 'host' AND JSON_EXTRACT(props_json, '$.authority') = '192.168.1.1'
   */
  findByKind(kind: NodeKind, filters?: Record<string, unknown>): GraphNode[] {
    if (filters === undefined || Object.keys(filters).length === 0) {
      const rows = this.selectByKindStmt.all(kind) as NodeRow[];
      return rows.map(rowToGraphNode);
    }

    // 動的フィルタ構築（プリペアドステートメントで安全に）
    const filterKeys = Object.keys(filters);
    const whereClauses = filterKeys.map((_key) => `JSON_EXTRACT(props_json, '$.' || ?) = ?`);
    const sql = `SELECT id, kind, natural_key, props_json, evidence_artifact_id, created_at, updated_at
                 FROM nodes
                 WHERE kind = ? AND ${whereClauses.join(' AND ')}`;

    const params: unknown[] = [kind];
    for (const key of filterKeys) {
      params.push(key, filters[key]);
    }

    const rows = this.db.prepare(sql).all(...params) as NodeRow[];
    return rows.map(rowToGraphNode);
  }

  /**
   * natural_key でノードを取得する。存在しなければ undefined。
   */
  findByNaturalKey(naturalKey: string): GraphNode | undefined {
    const row = this.selectByNaturalKeyStmt.get(naturalKey) as NodeRow | undefined;
    if (row === undefined) {
      return undefined;
    }
    return rowToGraphNode(row);
  }

  /**
   * ノードの props を更新する。updated_at も自動更新される。
   *
   * @returns 更新後の GraphNode。id が存在しなければ undefined。
   * @throws props バリデーションエラー時
   */
  updateProps(id: string, props: Record<string, unknown>): GraphNode | undefined {
    // 既存ノードを取得して kind を確認
    const existing = this.findById(id);
    if (existing === undefined) {
      return undefined;
    }

    // props バリデーション
    const validation = validateProps(existing.kind, props);
    if (!validation.ok) {
      throw new Error(`Props validation failed for kind="${existing.kind}": ${validation.error}`);
    }

    const propsJson = JSON.stringify(validation.data);
    const timestamp = new Date().toISOString();

    this.updatePropsStmt.run(propsJson, timestamp, id);

    return this.findById(id);
  }

  /**
   * ノードを削除する。
   *
   * @returns 削除成功時 true、id が存在しない場合 false。
   */
  delete(id: string): boolean {
    const result = this.deleteStmt.run(id);
    return result.changes > 0;
  }
}
