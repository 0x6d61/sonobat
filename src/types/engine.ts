/**
 * sonobat — Engine layer type definitions
 *
 * Engine 層の入出力型。MCP / CLI / GraphQL 全てから再利用可能。
 */

// ============================================================
// Propose
// ============================================================

/** Proposer が返す単一のアクション提案。 */
export interface Action {
  /** アクション種別 */
  kind:
    | 'network_service_discovery'
    | 'web_endpoint_discovery'
    | 'vulnerability_discovery'
    | 'parameter_discovery'
    | 'value_collection'
    | 'value_fuzz'
    | 'vhost_discovery';
  /** 人間向けの説明 */
  description: string;
  /** 実行可能なコマンド例（ない場合は undefined） */
  command?: string;
  /** 対象エンティティの参照情報 */
  params: Record<string, unknown>;
}
