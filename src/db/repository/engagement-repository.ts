/**
 * sonobat — EngagementRepository
 *
 * engagements テーブルに対する CRUD 操作を提供する。
 * snake_case (DB) ↔ camelCase (TypeScript) の変換を内部で行う。
 */

import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { Engagement, CreateEngagementInput } from '../../types/operational.js';

// ---------------------------------------------------------------------------
// DB row 型
// ---------------------------------------------------------------------------

/** better-sqlite3 から返る engagements テーブルの行形状 */
interface EngagementRow {
  id: string;
  name: string;
  environment: string;
  scope_json: string;
  policy_json: string;
  schedule_cron: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Row → Engagement 変換
// ---------------------------------------------------------------------------

/** snake_case DB row を camelCase Engagement にマッピング */
function rowToEngagement(row: EngagementRow): Engagement {
  return {
    id: row.id,
    name: row.name,
    environment: row.environment,
    scopeJson: row.scope_json,
    policyJson: row.policy_json,
    ...(row.schedule_cron !== null ? { scheduleCron: row.schedule_cron } : {}),
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// ---------------------------------------------------------------------------
// camelCase → snake_case フィールドマッピング
// ---------------------------------------------------------------------------

/** CreateEngagementInput のキーから DB カラム名へのマッピング */
const FIELD_TO_COLUMN: Record<string, string> = {
  name: 'name',
  environment: 'environment',
  scopeJson: 'scope_json',
  policyJson: 'policy_json',
  scheduleCron: 'schedule_cron',
  status: 'status',
};

// ---------------------------------------------------------------------------
// EngagementRepository
// ---------------------------------------------------------------------------

/**
 * engagements テーブルの CRUD リポジトリ。
 *
 * - デフォルト値: environment='stg', scopeJson='{}', policyJson='{}', status='active'
 * - ID は crypto.randomUUID() で生成
 * - update() は動的 SQL で提供されたフィールドのみ SET する
 */
export class EngagementRepository {
  private readonly db: Database.Database;

  private readonly insertStmt: Database.Statement;
  private readonly selectByIdStmt: Database.Statement;
  private readonly selectByStatusStmt: Database.Statement;
  private readonly selectAllStmt: Database.Statement;
  private readonly deleteStmt: Database.Statement;

  constructor(db: Database.Database) {
    this.db = db;

    this.insertStmt = this.db.prepare(
      `INSERT INTO engagements (id, name, environment, scope_json, policy_json, schedule_cron, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    this.selectByIdStmt = this.db.prepare(
      `SELECT id, name, environment, scope_json, policy_json, schedule_cron, status, created_at, updated_at
       FROM engagements WHERE id = ?`,
    );

    this.selectByStatusStmt = this.db.prepare(
      `SELECT id, name, environment, scope_json, policy_json, schedule_cron, status, created_at, updated_at
       FROM engagements WHERE status = ?`,
    );

    this.selectAllStmt = this.db.prepare(
      `SELECT id, name, environment, scope_json, policy_json, schedule_cron, status, created_at, updated_at
       FROM engagements`,
    );

    this.deleteStmt = this.db.prepare(`DELETE FROM engagements WHERE id = ?`);
  }

  /**
   * Engagement を新規作成して返す。
   *
   * デフォルト値:
   * - environment: 'stg'
   * - scopeJson: '{}'
   * - policyJson: '{}'
   * - status: 'active'
   */
  create(input: CreateEngagementInput): Engagement {
    const id = crypto.randomUUID();
    const timestamp = new Date().toISOString();

    const environment = input.environment ?? 'stg';
    const scopeJson = input.scopeJson ?? '{}';
    const policyJson = input.policyJson ?? '{}';
    const scheduleCron = input.scheduleCron ?? null;
    const status = input.status ?? 'active';

    this.insertStmt.run(
      id,
      input.name,
      environment,
      scopeJson,
      policyJson,
      scheduleCron,
      status,
      timestamp,
      timestamp,
    );

    return {
      id,
      name: input.name,
      environment,
      scopeJson,
      policyJson,
      ...(scheduleCron !== null ? { scheduleCron } : {}),
      status,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
  }

  /**
   * ID で Engagement を取得する。存在しなければ undefined。
   */
  findById(id: string): Engagement | undefined {
    const row = this.selectByIdStmt.get(id) as EngagementRow | undefined;
    if (row === undefined) {
      return undefined;
    }
    return rowToEngagement(row);
  }

  /**
   * status で Engagement 一覧を取得する。
   */
  findByStatus(status: string): Engagement[] {
    const rows = this.selectByStatusStmt.all(status) as EngagementRow[];
    return rows.map(rowToEngagement);
  }

  /**
   * 全 Engagement を取得する。
   */
  list(): Engagement[] {
    const rows = this.selectAllStmt.all() as EngagementRow[];
    return rows.map(rowToEngagement);
  }

  /**
   * Engagement の指定フィールドを更新する。
   *
   * 提供されたフィールドのみ SET し、updated_at を自動更新する。
   * 存在しない ID の場合 undefined を返す。
   */
  update(id: string, fields: Partial<CreateEngagementInput>): Engagement | undefined {
    // 更新対象のフィールドがなくても updated_at は更新する
    const setClauses: string[] = [];
    const params: unknown[] = [];

    for (const [key, value] of Object.entries(fields)) {
      const column = FIELD_TO_COLUMN[key];
      if (column !== undefined) {
        setClauses.push(`${column} = ?`);
        params.push(value ?? null);
      }
    }

    // updated_at は常に更新
    const timestamp = new Date().toISOString();
    setClauses.push('updated_at = ?');
    params.push(timestamp);

    // WHERE id = ?
    params.push(id);

    const sql = `UPDATE engagements SET ${setClauses.join(', ')} WHERE id = ?`;
    const result = this.db.prepare(sql).run(...params);

    if (result.changes === 0) {
      return undefined;
    }

    return this.findById(id);
  }

  /**
   * Engagement を削除する。
   *
   * CASCADE により関連する runs なども同時に削除される。
   *
   * @returns 削除成功時 true、id が存在しない場合 false。
   */
  delete(id: string): boolean {
    const result = this.deleteStmt.run(id);
    return result.changes > 0;
  }
}
