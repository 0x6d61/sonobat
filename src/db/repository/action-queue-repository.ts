/**
 * sonobat — ActionQueueRepository
 *
 * action_queue テーブルに対する CRUD + ポーリング操作。
 * キューベースの非同期タスク管理を提供する。
 */

import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { ActionQueueItem, CreateActionInput } from '../../types/operational.js';

// ---------------------------------------------------------------------------
// DB row 型
// ---------------------------------------------------------------------------

/** better-sqlite3 から返る action_queue テーブルの行形状 */
interface ActionQueueRow {
  id: string;
  engagement_id: string;
  run_id: string | null;
  parent_action_id: string | null;
  kind: string;
  priority: number;
  dedupe_key: string;
  params_json: string;
  state: string;
  attempt_count: number;
  max_attempts: number;
  available_at: string;
  lease_owner: string | null;
  lease_expires_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Row → ActionQueueItem 変換
// ---------------------------------------------------------------------------

/** snake_case DB row を camelCase ActionQueueItem にマッピング */
function rowToActionQueueItem(row: ActionQueueRow): ActionQueueItem {
  return {
    id: row.id,
    engagementId: row.engagement_id,
    ...(row.run_id !== null ? { runId: row.run_id } : {}),
    ...(row.parent_action_id !== null ? { parentActionId: row.parent_action_id } : {}),
    kind: row.kind,
    priority: row.priority,
    dedupeKey: row.dedupe_key,
    paramsJson: row.params_json,
    state: row.state,
    attemptCount: row.attempt_count,
    maxAttempts: row.max_attempts,
    availableAt: row.available_at,
    ...(row.lease_owner !== null ? { leaseOwner: row.lease_owner } : {}),
    ...(row.lease_expires_at !== null ? { leaseExpiresAt: row.lease_expires_at } : {}),
    ...(row.last_error !== null ? { lastError: row.last_error } : {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// ---------------------------------------------------------------------------
// ActionQueueRepository
// ---------------------------------------------------------------------------

/**
 * action_queue テーブルの CRUD + ポーリング リポジトリ。
 *
 * - デフォルト値: priority=100, state='queued', paramsJson='{}', maxAttempts=3, availableAt=now
 * - ID は crypto.randomUUID() で生成
 * - poll() はアトミックな UPDATE ... RETURNING で排他的リース取得
 * - fail() はリトライ回数に応じてバックオフ or dead letter
 */
export class ActionQueueRepository {
  private readonly db: Database.Database;

  private readonly insertStmt: Database.Statement;
  private readonly selectByIdStmt: Database.Statement;
  private readonly pollStmt: Database.Statement;
  private readonly completeStmt: Database.Statement;
  private readonly requeueStmt: Database.Statement;
  private readonly deadLetterStmt: Database.Statement;
  private readonly selectByEngagementStmt: Database.Statement;
  private readonly selectByEngagementStateStmt: Database.Statement;
  private readonly cancelStmt: Database.Statement;

  private readonly failTx: Database.Transaction<(id: string, error: string) => boolean>;

  constructor(db: Database.Database) {
    this.db = db;

    this.insertStmt = this.db.prepare(
      `INSERT INTO action_queue
         (id, engagement_id, run_id, parent_action_id, kind, priority,
          dedupe_key, params_json, state, attempt_count, max_attempts,
          available_at, lease_owner, lease_expires_at, last_error,
          created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    this.selectByIdStmt = this.db.prepare(
      `SELECT id, engagement_id, run_id, parent_action_id, kind, priority,
              dedupe_key, params_json, state, attempt_count, max_attempts,
              available_at, lease_owner, lease_expires_at, last_error,
              created_at, updated_at
       FROM action_queue WHERE id = ?`,
    );

    this.pollStmt = this.db.prepare(
      `UPDATE action_queue
       SET state = 'running',
           lease_owner = ?,
           lease_expires_at = ?,
           attempt_count = attempt_count + 1,
           updated_at = ?
       WHERE id = (
         SELECT id FROM action_queue
         WHERE state = 'queued' AND available_at <= ?
         ORDER BY priority ASC, created_at ASC
         LIMIT 1
       )
       RETURNING *`,
    );

    this.completeStmt = this.db.prepare(
      `UPDATE action_queue
       SET state = 'succeeded', updated_at = ?
       WHERE id = ? AND state = 'running'`,
    );

    this.requeueStmt = this.db.prepare(
      `UPDATE action_queue
       SET state = 'queued',
           available_at = ?,
           last_error = ?,
           lease_owner = NULL,
           lease_expires_at = NULL,
           updated_at = ?
       WHERE id = ?`,
    );

    this.deadLetterStmt = this.db.prepare(
      `UPDATE action_queue
       SET state = 'failed',
           last_error = ?,
           updated_at = ?
       WHERE id = ?`,
    );

    this.selectByEngagementStmt = this.db.prepare(
      `SELECT id, engagement_id, run_id, parent_action_id, kind, priority,
              dedupe_key, params_json, state, attempt_count, max_attempts,
              available_at, lease_owner, lease_expires_at, last_error,
              created_at, updated_at
       FROM action_queue
       WHERE engagement_id = ?
       ORDER BY created_at DESC`,
    );

    this.selectByEngagementStateStmt = this.db.prepare(
      `SELECT id, engagement_id, run_id, parent_action_id, kind, priority,
              dedupe_key, params_json, state, attempt_count, max_attempts,
              available_at, lease_owner, lease_expires_at, last_error,
              created_at, updated_at
       FROM action_queue
       WHERE engagement_id = ? AND state = ?
       ORDER BY created_at DESC`,
    );

    this.cancelStmt = this.db.prepare(
      `UPDATE action_queue SET state = 'cancelled', updated_at = ? WHERE id = ?`,
    );

    // fail トランザクション: リトライ可能か dead letter かを判定
    this.failTx = this.db.transaction((id: string, error: string): boolean => {
      const item = this.findById(id);
      if (!item || item.state !== 'running') return false;

      const now = new Date().toISOString();

      if (item.attemptCount < item.maxAttempts) {
        // リトライ可能: バックオフ付きで再キュー
        const backoffSec = item.attemptCount * 30;
        const availableAt = new Date(Date.now() + backoffSec * 1000).toISOString();
        this.requeueStmt.run(availableAt, error, now, id);
      } else {
        // Dead letter: 最大リトライ回数に到達
        this.deadLetterStmt.run(error, now, id);
      }

      return true;
    });
  }

  /**
   * アクションをキューに追加して返す。
   *
   * デフォルト値:
   * - priority: 100
   * - state: 'queued'
   * - paramsJson: '{}'
   * - maxAttempts: 3
   * - availableAt: 現在時刻
   */
  enqueue(input: CreateActionInput): ActionQueueItem {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const priority = input.priority ?? 100;
    const state = input.state ?? 'queued';
    const paramsJson = input.paramsJson ?? '{}';
    const maxAttempts = input.maxAttempts ?? 3;
    const availableAt = input.availableAt ?? now;

    this.insertStmt.run(
      id,
      input.engagementId,
      input.runId ?? null,
      input.parentActionId ?? null,
      input.kind,
      priority,
      input.dedupeKey,
      paramsJson,
      state,
      0, // attempt_count
      maxAttempts,
      availableAt,
      null, // lease_owner
      null, // lease_expires_at
      null, // last_error
      now, // created_at
      now, // updated_at
    );

    return {
      id,
      engagementId: input.engagementId,
      ...(input.runId !== undefined ? { runId: input.runId } : {}),
      ...(input.parentActionId !== undefined ? { parentActionId: input.parentActionId } : {}),
      kind: input.kind,
      priority,
      dedupeKey: input.dedupeKey,
      paramsJson,
      state,
      attemptCount: 0,
      maxAttempts,
      availableAt,
      createdAt: now,
      updatedAt: now,
    };
  }

  /**
   * ID でアクションを取得する。存在しなければ undefined。
   */
  findById(id: string): ActionQueueItem | undefined {
    const row = this.selectByIdStmt.get(id) as ActionQueueRow | undefined;
    if (row === undefined) {
      return undefined;
    }
    return rowToActionQueueItem(row);
  }

  /**
   * キューから次のアクションをポーリングする。
   *
   * アトミックに state='running' に遷移し、リースを設定する。
   * available_at が現在時刻以前のもののうち、priority ASC → created_at ASC で最初の1件を取得。
   *
   * @param leaseOwner       リースオーナーの識別子（例: 'worker-1'）
   * @param leaseDurationSec リース期間（秒）。デフォルト 300秒。
   * @returns ポーリングしたアクション。キューが空なら undefined。
   */
  poll(leaseOwner: string, leaseDurationSec?: number): ActionQueueItem | undefined {
    const duration = leaseDurationSec ?? 300;
    const now = new Date();
    const nowIso = now.toISOString();
    const leaseExpiresAt = new Date(now.getTime() + duration * 1000).toISOString();

    const row = this.pollStmt.get(
      leaseOwner,
      leaseExpiresAt,
      nowIso,
      nowIso,
    ) as ActionQueueRow | undefined;

    if (row === undefined) {
      return undefined;
    }
    return rowToActionQueueItem(row);
  }

  /**
   * アクションを正常完了にする。
   *
   * state を 'succeeded' に遷移する。running 状態でない場合は更新されない。
   *
   * @returns 更新成功時 true、id が存在しないか running でない場合 false。
   */
  complete(id: string): boolean {
    const now = new Date().toISOString();
    const result = this.completeStmt.run(now, id);
    return result.changes > 0;
  }

  /**
   * アクションを失敗にする。
   *
   * attempt_count < max_attempts の場合: state='queued' に戻し、バックオフ付きで再スケジュール。
   * attempt_count >= max_attempts の場合: state='failed'（dead letter）。
   *
   * @param id    アクション ID
   * @param error エラーメッセージ
   * @returns 更新成功時 true、id が存在しないか running でない場合 false。
   */
  fail(id: string, error: string): boolean {
    return this.failTx(id, error);
  }

  /**
   * エンゲージメントに紐づくアクション一覧を取得する。
   *
   * @param engagementId エンゲージメント ID
   * @param state        フィルタする状態（省略時は全状態）
   * @returns アクション一覧（created_at DESC 順）
   */
  findByEngagement(engagementId: string, state?: string): ActionQueueItem[] {
    if (state !== undefined) {
      const rows = this.selectByEngagementStateStmt.all(engagementId, state) as ActionQueueRow[];
      return rows.map(rowToActionQueueItem);
    }
    const rows = this.selectByEngagementStmt.all(engagementId) as ActionQueueRow[];
    return rows.map(rowToActionQueueItem);
  }

  /**
   * アクションをキャンセルする。
   *
   * @returns キャンセル成功時 true、id が存在しない場合 false。
   */
  cancel(id: string): boolean {
    const now = new Date().toISOString();
    const result = this.cancelStmt.run(now, id);
    return result.changes > 0;
  }
}
