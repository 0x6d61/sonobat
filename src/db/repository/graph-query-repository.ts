/**
 * sonobat — GraphQueryRepository
 *
 * グラフ走査・パス探索・プリセットクエリを提供するリポジトリ。
 * WITH RECURSIVE CTE を活用した SQLite ネイティブなグラフ操作。
 */

import type Database from 'better-sqlite3';
import type { GraphNode, GraphEdge, NodeKind, EdgeKind } from '../../types/graph.js';

// ---------------------------------------------------------------------------
// Row → Entity マッピング
// ---------------------------------------------------------------------------

interface NodeRow {
  id: string;
  kind: string;
  natural_key: string;
  props_json: string;
  evidence_artifact_id: string | null;
  created_at: string;
  updated_at: string;
}

interface EdgeRow {
  id: string;
  kind: string;
  source_id: string;
  target_id: string;
  props_json: string;
  evidence_artifact_id: string | null;
  created_at: string;
}

function rowToNode(row: NodeRow): GraphNode {
  return {
    id: row.id,
    kind: row.kind as NodeKind,
    naturalKey: row.natural_key,
    propsJson: row.props_json,
    evidenceArtifactId: row.evidence_artifact_id ?? undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function rowToEdge(row: EdgeRow): GraphEdge {
  return {
    id: row.id,
    kind: row.kind as EdgeKind,
    sourceId: row.source_id,
    targetId: row.target_id,
    propsJson: row.props_json,
    evidenceArtifactId: row.evidence_artifact_id ?? undefined,
    createdAt: row.created_at,
  };
}

// ---------------------------------------------------------------------------
// 公開型
// ---------------------------------------------------------------------------

export interface TraversalResult {
  node: GraphNode;
  depth: number;
  path: string[]; // node IDs from start to this node
}

export interface PathResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
  length: number;
}

export type PresetResult = Record<string, unknown>[];

// ---------------------------------------------------------------------------
// GraphQueryRepository
// ---------------------------------------------------------------------------

/**
 * グラフ走査・パス探索・プリセットクエリを提供するリポジトリ。
 *
 * すべてのクエリはプリペアドステートメントを使用し、SQL インジェクションを防止。
 */
export class GraphQueryRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /**
   * 開始ノードから有向エッジを辿り、到達可能なノードを幅優先で返す。
   *
   * @param startId   開始ノード ID
   * @param maxDepth  最大探索深度（デフォルト: 10）
   * @param edgeKinds 辿るエッジ種別のフィルタ（省略時は全種別）
   * @returns 到達可能なノードのリスト（開始ノード自身は含まない）
   */
  traverse(startId: string, maxDepth?: number, edgeKinds?: EdgeKind[]): TraversalResult[] {
    const depth = maxDepth ?? 10;

    // 開始ノードの存在確認
    const startNode = this.db
      .prepare<[string], NodeRow>('SELECT * FROM nodes WHERE id = ?')
      .get(startId);
    if (!startNode) {
      return [];
    }

    // edgeKinds フィルタ用の条件構築
    let edgeFilter = '';
    const params: unknown[] = [startId, startId, depth];

    if (edgeKinds && edgeKinds.length > 0) {
      const placeholders = edgeKinds.map(() => '?').join(', ');
      edgeFilter = `AND e.kind IN (${placeholders})`;
      params.push(...edgeKinds);
    }

    const sql = `
      WITH RECURSIVE graph_walk(node_id, depth, path) AS (
        SELECT ?, 0, ?
        UNION ALL
        SELECT e.target_id, gw.depth + 1, gw.path || ',' || e.target_id
        FROM graph_walk gw
        JOIN edges e ON e.source_id = gw.node_id
        WHERE gw.depth < ?
          ${edgeFilter}
          AND instr(',' || gw.path || ',', ',' || e.target_id || ',') = 0
      )
      SELECT DISTINCT
        n.id, n.kind, n.natural_key, n.props_json,
        n.evidence_artifact_id, n.created_at, n.updated_at,
        gw.depth AS walk_depth,
        gw.path AS walk_path
      FROM graph_walk gw
      JOIN nodes n ON n.id = gw.node_id
      WHERE gw.depth > 0
      ORDER BY gw.depth ASC
    `;

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as Array<NodeRow & { walk_depth: number; walk_path: string }>;

    // 同一ノードが複数パスで到達可能な場合、最短パスのみ保持
    const seen = new Map<string, TraversalResult>();

    for (const row of rows) {
      if (!seen.has(row.id) || seen.get(row.id)!.depth > row.walk_depth) {
        seen.set(row.id, {
          node: rowToNode(row),
          depth: row.walk_depth,
          path: row.walk_path.split(','),
        });
      }
    }

    return Array.from(seen.values()).sort((a, b) => a.depth - b.depth);
  }

  /**
   * 開始ノードから有向エッジを辿り、到達可能な全ノードを返す。
   *
   * @param nodeId     開始ノード ID
   * @param targetKind フィルタ対象のノード種別（省略時は全種別）
   * @returns 到達可能なノードのリスト
   */
  reachableFrom(nodeId: string, targetKind?: NodeKind): GraphNode[] {
    // BFS を TypeScript 側で実装する
    const visited = new Set<string>();
    const queue: string[] = [nodeId];
    visited.add(nodeId);

    const results: GraphNode[] = [];

    const edgeStmt = this.db.prepare<[string], EdgeRow>('SELECT * FROM edges WHERE source_id = ?');
    const nodeStmt = this.db.prepare<[string], NodeRow>('SELECT * FROM nodes WHERE id = ?');

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      const edges = edgeStmt.all(currentId);

      for (const edge of edges) {
        if (!visited.has(edge.target_id)) {
          visited.add(edge.target_id);
          queue.push(edge.target_id);

          const targetNode = nodeStmt.get(edge.target_id);
          if (targetNode) {
            const graphNode = rowToNode(targetNode);
            if (targetKind === undefined || graphNode.kind === targetKind) {
              results.push(graphNode);
            }
          }
        }
      }
    }

    return results;
  }

  /**
   * 2 ノード間の最短パスを BFS で探索する。
   *
   * @param sourceId 起点ノード ID
   * @param targetId 終点ノード ID
   * @returns パス情報。パスが存在しない場合は undefined
   */
  shortestPath(sourceId: string, targetId: string): PathResult | undefined {
    const nodeStmt = this.db.prepare<[string], NodeRow>('SELECT * FROM nodes WHERE id = ?');

    // 同一ノードの場合
    if (sourceId === targetId) {
      const node = nodeStmt.get(sourceId);
      if (!node) {
        return undefined;
      }
      return {
        nodes: [rowToNode(node)],
        edges: [],
        length: 0,
      };
    }

    // BFS で最短パスを探索
    const edgeStmt = this.db.prepare<[string], EdgeRow>('SELECT * FROM edges WHERE source_id = ?');

    // parent[nodeId] = { parentId, edge }
    const parent = new Map<string, { parentId: string; edge: EdgeRow }>();
    const visited = new Set<string>();
    const queue: string[] = [sourceId];
    visited.add(sourceId);

    let found = false;

    while (queue.length > 0 && !found) {
      const currentId = queue.shift()!;
      const edges = edgeStmt.all(currentId);

      for (const edge of edges) {
        if (!visited.has(edge.target_id)) {
          visited.add(edge.target_id);
          parent.set(edge.target_id, { parentId: currentId, edge });
          if (edge.target_id === targetId) {
            found = true;
            break;
          }
          queue.push(edge.target_id);
        }
      }
    }

    if (!found) {
      return undefined;
    }

    // パスを逆順に再構築
    const pathNodeIds: string[] = [];
    const pathEdges: GraphEdge[] = [];

    let currentId = targetId;
    while (currentId !== sourceId) {
      pathNodeIds.unshift(currentId);
      const info = parent.get(currentId)!;
      pathEdges.unshift(rowToEdge(info.edge));
      currentId = info.parentId;
    }
    pathNodeIds.unshift(sourceId);

    // ノード情報を取得
    const nodes: GraphNode[] = [];
    for (const nid of pathNodeIds) {
      const row = nodeStmt.get(nid);
      if (row) {
        nodes.push(rowToNode(row));
      }
    }

    return {
      nodes,
      edges: pathEdges,
      length: pathEdges.length,
    };
  }

  /**
   * プリセットクエリを実行する。
   *
   * @param pattern プリセット名
   * @param params  パラメータ（プリセットによって異なる）
   * @returns クエリ結果の配列
   */
  runPreset(pattern: string, params?: Record<string, unknown>): PresetResult {
    switch (pattern) {
      case 'attack_surface':
        return this.presetAttackSurface();
      case 'critical_vulns':
        return this.presetCriticalVulns();
      case 'credential_exposure':
        return this.presetCredentialExposure();
      case 'unscanned_services':
        return this.presetUnscannedServices();
      case 'vuln_by_host':
        return this.presetVulnByHost();
      case 'reachable_services':
        return this.presetReachableServices(params);
      default:
        throw new Error(`Unknown preset pattern: ${pattern}`);
    }
  }

  // =========================================================================
  // プリセットクエリ実装
  // =========================================================================

  /**
   * attack_surface: host → service → endpoint → input の完全パスを返す。
   * input がないエンドポイントも含む（inputId は null）。
   */
  private presetAttackSurface(): PresetResult {
    const sql = `
      SELECT
        h.id AS host_id,
        h.props_json AS host_props,
        s.id AS service_id,
        s.props_json AS service_props,
        ep.id AS endpoint_id,
        ep.props_json AS endpoint_props,
        inp.id AS input_id,
        inp.props_json AS input_props
      FROM nodes h
      JOIN edges e_hs ON e_hs.source_id = h.id AND e_hs.kind = 'HOST_SERVICE'
      JOIN nodes s ON s.id = e_hs.target_id AND s.kind = 'service'
      JOIN edges e_se ON e_se.source_id = s.id AND e_se.kind = 'SERVICE_ENDPOINT'
      JOIN nodes ep ON ep.id = e_se.target_id AND ep.kind = 'endpoint'
      LEFT JOIN edges e_ei ON e_ei.source_id = ep.id AND e_ei.kind = 'ENDPOINT_INPUT'
      LEFT JOIN nodes inp ON inp.id = e_ei.target_id AND inp.kind = 'input'
      WHERE h.kind = 'host'
      ORDER BY h.id, s.id, ep.id, inp.id
    `;

    const rows = this.db.prepare(sql).all() as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      hostId: row.host_id,
      hostProps: row.host_props,
      serviceId: row.service_id,
      serviceProps: row.service_props,
      endpointId: row.endpoint_id,
      endpointProps: row.endpoint_props,
      inputId: row.input_id ?? null,
      inputProps: row.input_props ?? null,
    }));
  }

  /**
   * critical_vulns: severity が critical/high の脆弱性をホスト情報付きで返す。
   */
  private presetCriticalVulns(): PresetResult {
    const sql = `
      SELECT
        h.id AS host_id,
        h.props_json AS host_props,
        s.id AS service_id,
        s.props_json AS service_props,
        v.id AS vuln_id,
        v.props_json AS vuln_props,
        json_extract(v.props_json, '$.severity') AS severity,
        json_extract(v.props_json, '$.title') AS title
      FROM nodes v
      JOIN edges e_sv ON e_sv.target_id = v.id AND e_sv.kind = 'SERVICE_VULNERABILITY'
      JOIN nodes s ON s.id = e_sv.source_id AND s.kind = 'service'
      JOIN edges e_hs ON e_hs.target_id = s.id AND e_hs.kind = 'HOST_SERVICE'
      JOIN nodes h ON h.id = e_hs.source_id AND h.kind = 'host'
      WHERE v.kind = 'vulnerability'
        AND json_extract(v.props_json, '$.severity') IN ('critical', 'high')
      ORDER BY
        CASE json_extract(v.props_json, '$.severity')
          WHEN 'critical' THEN 0
          WHEN 'high' THEN 1
        END,
        h.id
    `;

    const rows = this.db.prepare(sql).all() as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      hostId: row.host_id,
      hostProps: row.host_props,
      serviceId: row.service_id,
      serviceProps: row.service_props,
      vulnId: row.vuln_id,
      vulnProps: row.vuln_props,
      severity: row.severity,
      title: row.title,
    }));
  }

  /**
   * credential_exposure: service → credential の全マッピングを返す。
   */
  private presetCredentialExposure(): PresetResult {
    const sql = `
      SELECT
        s.id AS service_id,
        s.props_json AS service_props,
        c.id AS credential_id,
        c.props_json AS credential_props
      FROM nodes c
      JOIN edges e_sc ON e_sc.target_id = c.id AND e_sc.kind = 'SERVICE_CREDENTIAL'
      JOIN nodes s ON s.id = e_sc.source_id AND s.kind = 'service'
      WHERE c.kind = 'credential'
      ORDER BY s.id, c.id
    `;

    const rows = this.db.prepare(sql).all() as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      serviceId: row.service_id,
      serviceProps: row.service_props,
      credentialId: row.credential_id,
      credentialProps: row.credential_props,
    }));
  }

  /**
   * unscanned_services: endpoint が 0 件のサービスを返す。
   */
  private presetUnscannedServices(): PresetResult {
    const sql = `
      SELECT
        s.id AS service_id,
        s.props_json AS service_props,
        h.id AS host_id,
        h.props_json AS host_props
      FROM nodes s
      JOIN edges e_hs ON e_hs.target_id = s.id AND e_hs.kind = 'HOST_SERVICE'
      JOIN nodes h ON h.id = e_hs.source_id AND h.kind = 'host'
      LEFT JOIN edges e_se ON e_se.source_id = s.id AND e_se.kind = 'SERVICE_ENDPOINT'
      WHERE s.kind = 'service'
        AND e_se.id IS NULL
      ORDER BY h.id, s.id
    `;

    const rows = this.db.prepare(sql).all() as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      serviceId: row.service_id,
      serviceProps: row.service_props,
      hostId: row.host_id,
      hostProps: row.host_props,
    }));
  }

  /**
   * vuln_by_host: ホスト別脆弱性カウントを返す。
   */
  private presetVulnByHost(): PresetResult {
    const sql = `
      SELECT
        h.id AS host_id,
        h.props_json AS host_props,
        COUNT(v.id) AS vuln_count
      FROM nodes h
      JOIN edges e_hs ON e_hs.source_id = h.id AND e_hs.kind = 'HOST_SERVICE'
      JOIN nodes s ON s.id = e_hs.target_id AND s.kind = 'service'
      JOIN edges e_sv ON e_sv.source_id = s.id AND e_sv.kind = 'SERVICE_VULNERABILITY'
      JOIN nodes v ON v.id = e_sv.target_id AND v.kind = 'vulnerability'
      WHERE h.kind = 'host'
      GROUP BY h.id
      ORDER BY vuln_count DESC
    `;

    const rows = this.db.prepare(sql).all() as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      hostId: row.host_id,
      hostProps: row.host_props,
      vulnCount: row.vuln_count,
    }));
  }

  /**
   * reachable_services: 指定 host から到達可能な全サービスを返す。
   */
  private presetReachableServices(params?: Record<string, unknown>): PresetResult {
    const hostId = params?.hostId as string | undefined;
    if (!hostId) {
      throw new Error('reachable_services preset requires hostId parameter');
    }

    const sql = `
      SELECT
        s.id AS service_id,
        s.props_json AS service_props,
        e_hs.kind AS edge_kind
      FROM edges e_hs
      JOIN nodes s ON s.id = e_hs.target_id AND s.kind = 'service'
      WHERE e_hs.source_id = ?
        AND e_hs.kind = 'HOST_SERVICE'
      ORDER BY s.id
    `;

    const rows = this.db.prepare(sql).all(hostId) as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      serviceId: row.service_id,
      serviceProps: row.service_props,
      edgeKind: row.edge_kind,
    }));
  }
}
