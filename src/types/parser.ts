/**
 * sonobat — Parser intermediate types
 *
 * パーサーは DB の ID を持たない中間表現を返す。
 * Normalizer が自然キー（authority, port 等）で DB を検索・upsert する。
 */

// ============================================================
// 中間表現（DB ID を持たない）
// ============================================================

/** ホストの中間表現 */
export interface ParsedHost {
  authority: string;
  authorityKind: 'IP' | 'DOMAIN';
  resolvedIps?: string[];
}

/** サービスの中間表現 */
export interface ParsedService {
  hostAuthority: string;
  transport: string;
  port: number;
  appProto: string;
  protoConfidence: string;
  banner?: string;
  product?: string;
  version?: string;
  state: string;
}

/** サービス観測の中間表現 */
export interface ParsedServiceObservation {
  hostAuthority: string;
  transport: string;
  port: number;
  key: string;
  value: string;
  confidence: string;
}

/** HTTP エンドポイントの中間表現 */
export interface ParsedHttpEndpoint {
  hostAuthority: string;
  port: number;
  baseUri: string;
  method: string;
  path: string;
  statusCode?: number;
  contentLength?: number;
  words?: number;
  lines?: number;
}

/** 入力パラメータの中間表現 */
export interface ParsedInput {
  hostAuthority: string;
  port: number;
  location: string;
  name: string;
  typeHint?: string;
}

/** エンドポイント ↔ 入力の紐づけ中間表現 */
export interface ParsedEndpointInput {
  hostAuthority: string;
  port: number;
  method: string;
  path: string;
  inputLocation: string;
  inputName: string;
}

/** 観測値の中間表現 */
export interface ParsedObservation {
  hostAuthority: string;
  port: number;
  inputLocation: string;
  inputName: string;
  rawValue: string;
  normValue: string;
  source: string;
  confidence: string;
}

/** 脆弱性の中間表現 */
export interface ParsedVulnerability {
  hostAuthority: string;
  port: number;
  method?: string;
  path?: string;
  vulnType: string;
  title: string;
  description?: string;
  severity: string;
  confidence: string;
}

/** CVE の中間表現 */
export interface ParsedCve {
  /** 対応する脆弱性の title（紐づけ用） */
  vulnerabilityTitle: string;
  cveId: string;
  description?: string;
  cvssScore?: number;
  cvssVector?: string;
  referenceUrl?: string;
}

// ============================================================
// パース結果
// ============================================================

/** パーサーが返す統一的な結果型 */
export interface ParseResult {
  hosts: ParsedHost[];
  services: ParsedService[];
  serviceObservations: ParsedServiceObservation[];
  httpEndpoints: ParsedHttpEndpoint[];
  inputs: ParsedInput[];
  endpointInputs: ParsedEndpointInput[];
  observations: ParsedObservation[];
  vulnerabilities: ParsedVulnerability[];
  cves: ParsedCve[];
}

/** 空の ParseResult を生成するユーティリティ */
export function emptyParseResult(): ParseResult {
  return {
    hosts: [],
    services: [],
    serviceObservations: [],
    httpEndpoints: [],
    inputs: [],
    endpointInputs: [],
    observations: [],
    vulnerabilities: [],
    cves: [],
  };
}
