/**
 * sonobat — ActionExecutionRepository
 *
 * action_executions テーブルに対する CRUD 操作を提供する。
 * snake_case (DB) <-> camelCase (TypeScript) の変換を内部で行う。
 */

import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { ActionExecution, CreateExecutionInput } from '../../types/operational.js';

// ---------------------------------------------------------------------------
// DB row 型
// ---------------------------------------------------------------------------

/** better-sqlite3 から返る action_executions テーブルの行形状 */
interface ActionExecutionRow {
  id: string;
  action_id: string;
  run_id: string | null;
  executor: string;
  command: string | null;
  input_json: string;
  output_json: string;
  stdout_artifact_id: string | null;
  stderr_artifact_id: string | null;
  exit_code: number | null;
  error_type: string | null;
  error_message: string | null;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
}

// ---------------------------------------------------------------------------
// Row → ActionExecution 変換
// ---------------------------------------------------------------------------

/** snake_case DB row を camelCase ActionExecution にマッピング */
function rowToExecution(row: ActionExecutionRow): ActionExecution {
  return {
    id: row.id,
    actionId: row.action_id,
    ...(row.run_id !== null ? { runId: row.run_id } : {}),
    executor: row.executor,
    ...(row.command !== null ? { command: row.command } : {}),
    inputJson: row.input_json,
    outputJson: row.output_json,
    ...(row.stdout_artifact_id !== null ? { stdoutArtifactId: row.stdout_artifact_id } : {}),
    ...(row.stderr_artifact_id !== null ? { stderrArtifactId: row.stderr_artifact_id } : {}),
    ...(row.exit_code !== null ? { exitCode: row.exit_code } : {}),
    ...(row.error_type !== null ? { errorType: row.error_type } : {}),
    ...(row.error_message !== null ? { errorMessage: row.error_message } : {}),
    startedAt: row.started_at,
    ...(row.finished_at !== null ? { finishedAt: row.finished_at } : {}),
    ...(row.duration_ms !== null ? { durationMs: row.duration_ms } : {}),
  };
}

// ---------------------------------------------------------------------------
// Complete output 型
// ---------------------------------------------------------------------------

/** complete() に渡す出力パラメータ */
export interface CompleteExecutionOutput {
  outputJson?: string;
  exitCode?: number;
  errorType?: string;
  errorMessage?: string;
  stdoutArtifactId?: string;
  stderrArtifactId?: string;
}

// ---------------------------------------------------------------------------
// ActionExecutionRepository
// ---------------------------------------------------------------------------

/**
 * action_executions テーブルの CRUD リポジトリ。
 *
 * - ID は crypto.randomUUID() で生成
 * - started_at は create 時に自動設定
 * - complete() で finished_at, duration_ms を自動計算
 */
export class ActionExecutionRepository {
  private readonly db: Database.Database;

  private readonly insertStmt: Database.Statement;
  private readonly selectByIdStmt: Database.Statement;
  private readonly selectByActionStmt: Database.Statement;
  private readonly selectByRunStmt: Database.Statement;

  constructor(db: Database.Database) {
    this.db = db;

    this.insertStmt = this.db.prepare(
      `INSERT INTO action_executions (id, action_id, run_id, executor, command, input_json, output_json, started_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    this.selectByIdStmt = this.db.prepare(
      `SELECT id, action_id, run_id, executor, command, input_json, output_json,
              stdout_artifact_id, stderr_artifact_id, exit_code, error_type, error_message,
              started_at, finished_at, duration_ms
       FROM action_executions WHERE id = ?`,
    );

    this.selectByActionStmt = this.db.prepare(
      `SELECT id, action_id, run_id, executor, command, input_json, output_json,
              stdout_artifact_id, stderr_artifact_id, exit_code, error_type, error_message,
              started_at, finished_at, duration_ms
       FROM action_executions WHERE action_id = ? ORDER BY started_at DESC`,
    );

    this.selectByRunStmt = this.db.prepare(
      `SELECT id, action_id, run_id, executor, command, input_json, output_json,
              stdout_artifact_id, stderr_artifact_id, exit_code, error_type, error_message,
              started_at, finished_at, duration_ms
       FROM action_executions WHERE run_id = ? ORDER BY started_at DESC`,
    );
  }

  /**
   * ActionExecution を新規作成して返す。
   *
   * - started_at は現在時刻に自動設定
   * - inputJson デフォルト '{}'
   * - outputJson デフォルト '{}'
   */
  create(input: CreateExecutionInput): ActionExecution {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const inputJson = input.inputJson ?? '{}';

    this.insertStmt.run(
      id,
      input.actionId,
      input.runId ?? null,
      input.executor,
      input.command ?? null,
      inputJson,
      '{}', // output_json default
      now, // started_at
    );

    return {
      id,
      actionId: input.actionId,
      ...(input.runId !== undefined ? { runId: input.runId } : {}),
      executor: input.executor,
      ...(input.command !== undefined ? { command: input.command } : {}),
      inputJson,
      outputJson: '{}',
      startedAt: now,
    };
  }

  /**
   * ID で ActionExecution を取得する。存在しなければ undefined。
   */
  findById(id: string): ActionExecution | undefined {
    const row = this.selectByIdStmt.get(id) as ActionExecutionRow | undefined;
    if (row === undefined) {
      return undefined;
    }
    return rowToExecution(row);
  }

  /**
   * action_id で ActionExecution 一覧を取得する。
   * ORDER BY started_at DESC。
   */
  findByAction(actionId: string): ActionExecution[] {
    const rows = this.selectByActionStmt.all(actionId) as ActionExecutionRow[];
    return rows.map(rowToExecution);
  }

  /**
   * run_id で ActionExecution 一覧を取得する。
   * ORDER BY started_at DESC。
   */
  findByRun(runId: string): ActionExecution[] {
    const rows = this.selectByRunStmt.all(runId) as ActionExecutionRow[];
    return rows.map(rowToExecution);
  }

  /**
   * ActionExecution を完了状態にする。
   *
   * - finished_at を現在時刻に設定
   * - duration_ms を started_at からの差分で自動計算
   * - outputJson, exitCode, errorType, errorMessage を更新
   *
   * @returns 更新後の ActionExecution。id が存在しなければ undefined。
   */
  complete(id: string, output: CompleteExecutionOutput): ActionExecution | undefined {
    const existing = this.findById(id);
    if (existing === undefined) {
      return undefined;
    }

    const now = new Date();
    const finishedAt = now.toISOString();
    const durationMs = now.getTime() - new Date(existing.startedAt).getTime();

    const setClauses: string[] = ['finished_at = ?', 'duration_ms = ?'];
    const params: unknown[] = [finishedAt, durationMs];

    if (output.outputJson !== undefined) {
      setClauses.push('output_json = ?');
      params.push(output.outputJson);
    }
    if (output.exitCode !== undefined) {
      setClauses.push('exit_code = ?');
      params.push(output.exitCode);
    }
    if (output.errorType !== undefined) {
      setClauses.push('error_type = ?');
      params.push(output.errorType);
    }
    if (output.errorMessage !== undefined) {
      setClauses.push('error_message = ?');
      params.push(output.errorMessage);
    }
    if (output.stdoutArtifactId !== undefined) {
      setClauses.push('stdout_artifact_id = ?');
      params.push(output.stdoutArtifactId);
    }
    if (output.stderrArtifactId !== undefined) {
      setClauses.push('stderr_artifact_id = ?');
      params.push(output.stderrArtifactId);
    }

    params.push(id);

    const sql = `UPDATE action_executions SET ${setClauses.join(', ')} WHERE id = ?`;
    this.db.prepare(sql).run(...params);

    return this.findById(id);
  }
}
