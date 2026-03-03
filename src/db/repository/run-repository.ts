/**
 * sonobat — RunRepository
 *
 * runs テーブルに対する CRUD 操作を提供する。
 * snake_case (DB) ↔ camelCase (TypeScript) の変換を内部で行う。
 */

import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { Run, CreateRunInput } from '../../types/operational.js';

// ---------------------------------------------------------------------------
// DB row 型
// ---------------------------------------------------------------------------

/** better-sqlite3 から返る runs テーブルの行形状 */
interface RunRow {
  id: string;
  engagement_id: string;
  trigger_kind: string;
  trigger_ref: string | null;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  summary_json: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Row → Run 変換
// ---------------------------------------------------------------------------

/** snake_case DB row を camelCase Run にマッピング */
function rowToRun(row: RunRow): Run {
  return {
    id: row.id,
    engagementId: row.engagement_id,
    triggerKind: row.trigger_kind,
    ...(row.trigger_ref !== null ? { triggerRef: row.trigger_ref } : {}),
    status: row.status,
    ...(row.started_at !== null ? { startedAt: row.started_at } : {}),
    ...(row.finished_at !== null ? { finishedAt: row.finished_at } : {}),
    summaryJson: row.summary_json,
    createdAt: row.created_at,
  };
}

// ---------------------------------------------------------------------------
// RunRepository
// ---------------------------------------------------------------------------

/**
 * runs テーブルの CRUD リポジトリ。
 *
 * - ID は crypto.randomUUID() で生成
 * - created_at / started_at / finished_at は状況に応じて自動設定
 */
export class RunRepository {
  private readonly db: Database.Database;

  private readonly insertStmt: Database.Statement;
  private readonly selectByIdStmt: Database.Statement;
  private readonly selectByEngagementStmt: Database.Statement;
  private readonly selectByStatusStmt: Database.Statement;
  private readonly deleteStmt: Database.Statement;

  constructor(db: Database.Database) {
    this.db = db;

    this.insertStmt = this.db.prepare(
      `INSERT INTO runs (id, engagement_id, trigger_kind, trigger_ref, status, started_at, finished_at, summary_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    this.selectByIdStmt = this.db.prepare(
      `SELECT id, engagement_id, trigger_kind, trigger_ref, status, started_at, finished_at, summary_json, created_at
       FROM runs WHERE id = ?`,
    );

    this.selectByEngagementStmt = this.db.prepare(
      `SELECT id, engagement_id, trigger_kind, trigger_ref, status, started_at, finished_at, summary_json, created_at
       FROM runs WHERE engagement_id = ? ORDER BY created_at DESC LIMIT ?`,
    );

    this.selectByStatusStmt = this.db.prepare(
      `SELECT id, engagement_id, trigger_kind, trigger_ref, status, started_at, finished_at, summary_json, created_at
       FROM runs WHERE status = ?`,
    );

    this.deleteStmt = this.db.prepare(`DELETE FROM runs WHERE id = ?`);
  }

  /**
   * Run を新規作成して返す。
   *
   * - created_at は現在時刻に設定
   * - status が 'running' の場合、started_at も現在時刻に設定
   * - summaryJson はデフォルト '{}'
   */
  create(input: CreateRunInput): Run {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const startedAt = input.status === 'running' ? now : null;

    this.insertStmt.run(
      id,
      input.engagementId,
      input.triggerKind,
      input.triggerRef ?? null,
      input.status,
      startedAt,
      null, // finished_at
      '{}', // summary_json
      now, // created_at
    );

    return {
      id,
      engagementId: input.engagementId,
      triggerKind: input.triggerKind,
      ...(input.triggerRef !== undefined ? { triggerRef: input.triggerRef } : {}),
      status: input.status,
      ...(startedAt !== null ? { startedAt } : {}),
      summaryJson: '{}',
      createdAt: now,
    };
  }

  /**
   * ID で Run を取得する。存在しなければ undefined。
   */
  findById(id: string): Run | undefined {
    const row = this.selectByIdStmt.get(id) as RunRow | undefined;
    if (row === undefined) {
      return undefined;
    }
    return rowToRun(row);
  }

  /**
   * engagement_id で Run 一覧を取得する。
   * ORDER BY created_at DESC、LIMIT デフォルト 100。
   */
  findByEngagement(engagementId: string, limit?: number): Run[] {
    const rows = this.selectByEngagementStmt.all(engagementId, limit ?? 100) as RunRow[];
    return rows.map(rowToRun);
  }

  /**
   * status で Run 一覧を取得する。
   */
  findByStatus(status: string): Run[] {
    const rows = this.selectByStatusStmt.all(status) as RunRow[];
    return rows.map(rowToRun);
  }

  /**
   * Run のステータスを更新する。
   *
   * - 'succeeded' または 'failed' の場合、finished_at を現在時刻に設定
   * - 'running' の場合、started_at が未設定なら現在時刻に設定
   * - summaryJson が指定された場合、summary_json も更新
   *
   * @returns 更新後の Run。id が存在しなければ undefined。
   */
  updateStatus(id: string, status: string, summaryJson?: string): Run | undefined {
    // 既存レコードを確認
    const existing = this.findById(id);
    if (existing === undefined) {
      return undefined;
    }

    // 完了済み Run の二重完了を防止
    if (existing.status === 'succeeded' || existing.status === 'failed') {
      return undefined;
    }

    const now = new Date().toISOString();

    // 動的に SET 句を構築
    const setClauses: string[] = ['status = ?'];
    const params: unknown[] = [status];

    // finished_at: succeeded / failed の場合に設定
    if (status === 'succeeded' || status === 'failed') {
      setClauses.push('finished_at = ?');
      params.push(now);
    }

    // started_at: running に遷移し、まだ未設定の場合に設定
    if (status === 'running' && existing.startedAt === undefined) {
      setClauses.push('started_at = ?');
      params.push(now);
    }

    // summaryJson: 指定された場合に更新
    if (summaryJson !== undefined) {
      setClauses.push('summary_json = ?');
      params.push(summaryJson);
    }

    params.push(id);

    const sql = `UPDATE runs SET ${setClauses.join(', ')} WHERE id = ?`;
    this.db.prepare(sql).run(...params);

    return this.findById(id);
  }

  /**
   * Run を削除する。
   *
   * @returns 削除成功時 true、id が存在しない場合 false。
   */
  delete(id: string): boolean {
    const result = this.deleteStmt.run(id);
    return result.changes > 0;
  }
}
