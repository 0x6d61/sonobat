/**
 * sonobat — RiskSnapshotRepository
 *
 * risk_snapshots テーブルに対する CRUD 操作。
 * エンゲージメントごとのリスクスコア時系列管理を提供する。
 */

import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { RiskSnapshot, CreateRiskSnapshotInput } from '../../types/operational.js';

// ---------------------------------------------------------------------------
// DB row 型
// ---------------------------------------------------------------------------

/** better-sqlite3 から返る risk_snapshots テーブルの行形状 */
interface RiskSnapshotRow {
  id: string;
  engagement_id: string;
  run_id: string | null;
  score: number;
  open_critical: number;
  open_high: number;
  open_medium: number;
  open_low: number;
  open_info: number;
  open_total: number;
  attack_path_count: number;
  exposed_cred_count: number;
  model_version: string | null;
  attrs_json: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Row → RiskSnapshot 変換
// ---------------------------------------------------------------------------

/** snake_case DB row を camelCase RiskSnapshot にマッピング */
function rowToRiskSnapshot(row: RiskSnapshotRow): RiskSnapshot {
  return {
    id: row.id,
    engagementId: row.engagement_id,
    ...(row.run_id !== null ? { runId: row.run_id } : {}),
    score: row.score,
    openCritical: row.open_critical,
    openHigh: row.open_high,
    openMedium: row.open_medium,
    openLow: row.open_low,
    openInfo: row.open_info,
    openTotal: row.open_total,
    attackPathCount: row.attack_path_count,
    exposedCredCount: row.exposed_cred_count,
    ...(row.model_version !== null ? { modelVersion: row.model_version } : {}),
    attrsJson: row.attrs_json,
    createdAt: row.created_at,
  };
}

// ---------------------------------------------------------------------------
// RiskSnapshotRepository
// ---------------------------------------------------------------------------

/**
 * risk_snapshots テーブルの CRUD リポジトリ。
 *
 * - デフォルト値: 全 integer フィールドは 0、attrsJson は '{}'、created_at は現在時刻
 * - ID は crypto.randomUUID() で生成
 * - findByEngagement() は created_at DESC でソートし、デフォルト limit は 100
 * - latest() は最新のスナップショットを1件返す
 */
export class RiskSnapshotRepository {
  private readonly db: Database.Database;

  private readonly insertStmt: Database.Statement;
  private readonly selectByIdStmt: Database.Statement;
  private readonly selectByEngagementStmt: Database.Statement;
  private readonly latestStmt: Database.Statement;

  constructor(db: Database.Database) {
    this.db = db;

    this.insertStmt = this.db.prepare(
      `INSERT INTO risk_snapshots
         (id, engagement_id, run_id, score,
          open_critical, open_high, open_medium, open_low, open_info, open_total,
          attack_path_count, exposed_cred_count, model_version,
          attrs_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    this.selectByIdStmt = this.db.prepare(
      `SELECT id, engagement_id, run_id, score,
              open_critical, open_high, open_medium, open_low, open_info, open_total,
              attack_path_count, exposed_cred_count, model_version,
              attrs_json, created_at
       FROM risk_snapshots WHERE id = ?`,
    );

    this.selectByEngagementStmt = this.db.prepare(
      `SELECT id, engagement_id, run_id, score,
              open_critical, open_high, open_medium, open_low, open_info, open_total,
              attack_path_count, exposed_cred_count, model_version,
              attrs_json, created_at
       FROM risk_snapshots
       WHERE engagement_id = ?
       ORDER BY created_at DESC
       LIMIT ?`,
    );

    this.latestStmt = this.db.prepare(
      `SELECT id, engagement_id, run_id, score,
              open_critical, open_high, open_medium, open_low, open_info, open_total,
              attack_path_count, exposed_cred_count, model_version,
              attrs_json, created_at
       FROM risk_snapshots
       WHERE engagement_id = ?
       ORDER BY created_at DESC
       LIMIT 1`,
    );
  }

  /**
   * RiskSnapshot を新規作成して返す。
   *
   * デフォルト値:
   * - openCritical, openHigh, openMedium, openLow, openInfo, openTotal: 0
   * - attackPathCount: 0
   * - exposedCredCount: 0
   * - attrsJson: '{}'
   * - createdAt: 現在時刻（ISO 8601）
   */
  create(input: CreateRiskSnapshotInput): RiskSnapshot {
    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();

    const runId = input.runId ?? null;
    const openCritical = input.openCritical ?? 0;
    const openHigh = input.openHigh ?? 0;
    const openMedium = input.openMedium ?? 0;
    const openLow = input.openLow ?? 0;
    const openInfo = input.openInfo ?? 0;
    const openTotal = input.openTotal ?? 0;
    const attackPathCount = input.attackPathCount ?? 0;
    const exposedCredCount = input.exposedCredCount ?? 0;
    const modelVersion = input.modelVersion ?? null;
    const attrsJson = input.attrsJson ?? '{}';

    this.insertStmt.run(
      id,
      input.engagementId,
      runId,
      input.score,
      openCritical,
      openHigh,
      openMedium,
      openLow,
      openInfo,
      openTotal,
      attackPathCount,
      exposedCredCount,
      modelVersion,
      attrsJson,
      createdAt,
    );

    return {
      id,
      engagementId: input.engagementId,
      ...(runId !== null ? { runId } : {}),
      score: input.score,
      openCritical,
      openHigh,
      openMedium,
      openLow,
      openInfo,
      openTotal,
      attackPathCount,
      exposedCredCount,
      ...(modelVersion !== null ? { modelVersion } : {}),
      attrsJson,
      createdAt,
    };
  }

  /**
   * ID で RiskSnapshot を取得する。存在しなければ undefined。
   */
  findById(id: string): RiskSnapshot | undefined {
    const row = this.selectByIdStmt.get(id) as RiskSnapshotRow | undefined;
    if (row === undefined) {
      return undefined;
    }
    return rowToRiskSnapshot(row);
  }

  /**
   * エンゲージメントに紐づく RiskSnapshot 一覧を取得する。
   *
   * created_at DESC でソートし、limit で件数を制限する（デフォルト 100）。
   *
   * @param engagementId エンゲージメント ID
   * @param limit        最大取得件数（デフォルト 100）
   * @returns RiskSnapshot 一覧（created_at DESC 順）
   */
  findByEngagement(engagementId: string, limit?: number): RiskSnapshot[] {
    const effectiveLimit = limit ?? 100;
    const rows = this.selectByEngagementStmt.all(engagementId, effectiveLimit) as RiskSnapshotRow[];
    return rows.map(rowToRiskSnapshot);
  }

  /**
   * エンゲージメントの最新 RiskSnapshot を取得する。
   *
   * スナップショットが存在しない場合は undefined を返す。
   *
   * @param engagementId エンゲージメント ID
   * @returns 最新の RiskSnapshot、または undefined
   */
  latest(engagementId: string): RiskSnapshot | undefined {
    const row = this.latestStmt.get(engagementId) as RiskSnapshotRow | undefined;
    if (row === undefined) {
      return undefined;
    }
    return rowToRiskSnapshot(row);
  }
}
