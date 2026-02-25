/**
 * sonobat — Nuclei JSONL パーサー
 *
 * nuclei の JSONL 出力を解析し、ParseResult 中間表現を返す。
 * 各行は独立した JSON オブジェクト（nuclei finding）として処理する。
 */

import type {
  ParseResult,
  ParsedHost,
  ParsedService,
  ParsedHttpEndpoint,
  ParsedVulnerability,
  ParsedCve,
} from '../types/parser.js';
import { emptyParseResult } from '../types/parser.js';

// ============================================================
// nuclei finding の型定義（unknown から安全に取り出すための構造）
// ============================================================

interface NucleiClassification {
  'cve-id'?: string[];
  'cvss-metrics'?: string;
  'cvss-score'?: number;
}

interface NucleiInfo {
  name: string;
  severity: string;
  tags: string[];
  classification?: NucleiClassification;
}

interface NucleiFinding {
  'template-id': string;
  info: NucleiInfo;
  type: string;
  host: string;
  'matched-at': string;
  ip: string;
  port: string;
  scheme: string;
  url: string;
}

// ============================================================
// 型ガード
// ============================================================

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === 'string')
  );
}

function isNucleiClassification(
  value: unknown,
): value is NucleiClassification {
  if (!isRecord(value)) return false;
  // classification は空オブジェクトでも許容する
  if ('cve-id' in value && !isStringArray(value['cve-id'])) return false;
  if (
    'cvss-metrics' in value &&
    typeof value['cvss-metrics'] !== 'string' &&
    value['cvss-metrics'] !== undefined
  )
    return false;
  if (
    'cvss-score' in value &&
    typeof value['cvss-score'] !== 'number' &&
    value['cvss-score'] !== undefined
  )
    return false;
  return true;
}

function isNucleiInfo(value: unknown): value is NucleiInfo {
  if (!isRecord(value)) return false;
  if (typeof value.name !== 'string') return false;
  if (typeof value.severity !== 'string') return false;
  if (!isStringArray(value.tags)) return false;
  if (
    'classification' in value &&
    value.classification !== undefined &&
    !isNucleiClassification(value.classification)
  )
    return false;
  return true;
}

function isNucleiFinding(value: unknown): value is NucleiFinding {
  if (!isRecord(value)) return false;
  if (typeof value['template-id'] !== 'string') return false;
  if (!isNucleiInfo(value.info)) return false;
  if (typeof value.type !== 'string') return false;
  if (typeof value.host !== 'string') return false;
  if (typeof value['matched-at'] !== 'string') return false;
  if (typeof value.ip !== 'string') return false;
  if (typeof value.port !== 'string') return false;
  if (typeof value.scheme !== 'string') return false;
  if (typeof value.url !== 'string') return false;
  return true;
}

// ============================================================
// URL パス抽出（生文字列から、デコードせずに抽出する）
// ============================================================

/**
 * URL 文字列から pathname 部分を生文字列のまま抽出する。
 * Node.js の URL クラスは %2e を . にデコードしてパスを正規化してしまうため、
 * パストラバーサル系のペイロードを保存するには raw なパスが必要。
 */
function extractRawPathname(urlStr: string): string {
  // scheme://authority の後のパス部分を取り出す
  // authority の終わり = 3つ目の / の位置（scheme://host:port/path...）
  const schemeEnd = urlStr.indexOf('://');
  if (schemeEnd === -1) {
    return '/';
  }
  const afterAuthority = urlStr.indexOf('/', schemeEnd + 3);
  if (afterAuthority === -1) {
    return '/';
  }
  // パスの終わり = ? または # の最初の出現位置
  const queryStart = urlStr.indexOf('?', afterAuthority);
  const fragmentStart = urlStr.indexOf('#', afterAuthority);
  let pathEnd = urlStr.length;
  if (queryStart !== -1 && queryStart < pathEnd) {
    pathEnd = queryStart;
  }
  if (fragmentStart !== -1 && fragmentStart < pathEnd) {
    pathEnd = fragmentStart;
  }
  return urlStr.substring(afterAuthority, pathEnd);
}

// ============================================================
// vulnType 推定
// ============================================================

/** タグ配列から vulnType を推定する。優先度順に判定する。 */
function inferVulnType(tags: string[]): string {
  const priorityTags = ['sqli', 'xss', 'rce', 'lfi', 'ssrf'] as const;
  for (const tag of priorityTags) {
    if (tags.includes(tag)) {
      return tag;
    }
  }
  return 'other';
}

// ============================================================
// メインパーサー
// ============================================================

/**
 * nuclei JSONL 出力をパースし、ParseResult を返す。
 *
 * @param jsonl - nuclei の JSONL 出力文字列（1行1JSON）
 * @returns ParseResult 中間表現
 */
export function parseNucleiJsonl(jsonl: string): ParseResult {
  const result = emptyParseResult();

  if (jsonl.trim() === '') {
    return result;
  }

  const lines = jsonl.split('\n');
  const seenHosts = new Set<string>();
  const seenServices = new Set<string>();

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '') {
      continue;
    }

    const parsed: unknown = JSON.parse(trimmed);
    if (!isNucleiFinding(parsed)) {
      continue;
    }

    processFinding(parsed, result, seenHosts, seenServices);
  }

  return result;
}

/**
 * 単一の nuclei finding を処理し、結果に追加する。
 */
function processFinding(
  finding: NucleiFinding,
  result: ParseResult,
  seenHosts: Set<string>,
  seenServices: Set<string>,
): void {
  const ip = finding.ip;
  const port = Number(finding.port);
  const scheme = finding.scheme;
  const matchedAt = finding['matched-at'];

  // --- ホスト（重複排除） ---
  if (!seenHosts.has(ip)) {
    seenHosts.add(ip);
    const host: ParsedHost = {
      authority: ip,
      authorityKind: 'IP',
    };
    result.hosts.push(host);
  }

  // --- サービス（authority+port で重複排除） ---
  const serviceKey = `${ip}:${port}`;
  if (!seenServices.has(serviceKey)) {
    seenServices.add(serviceKey);
    const service: ParsedService = {
      hostAuthority: ip,
      transport: 'tcp',
      port,
      appProto: scheme,
      protoConfidence: 'high',
      state: 'open',
    };
    result.services.push(service);
  }

  // --- HTTP エンドポイント ---
  const rawPath = extractRawPathname(matchedAt);
  const baseUri = `${scheme}://${ip}:${port}`;

  const endpoint: ParsedHttpEndpoint = {
    hostAuthority: ip,
    port,
    baseUri,
    method: 'GET',
    path: rawPath,
  };
  result.httpEndpoints.push(endpoint);

  // --- 脆弱性 ---
  const info = finding.info;
  const vulnerability: ParsedVulnerability = {
    hostAuthority: ip,
    port,
    method: 'GET',
    path: rawPath,
    vulnType: inferVulnType(info.tags),
    title: info.name,
    severity: info.severity,
    confidence: 'high',
  };
  result.vulnerabilities.push(vulnerability);

  // --- CVE ---
  const classification = info.classification;
  if (
    classification !== undefined &&
    isRecord(classification) &&
    'cve-id' in classification &&
    isStringArray(classification['cve-id']) &&
    classification['cve-id'].length > 0
  ) {
    for (const cveId of classification['cve-id']) {
      const cve: ParsedCve = {
        vulnerabilityTitle: info.name,
        cveId,
        cvssScore: classification['cvss-score'],
        cvssVector: classification['cvss-metrics'],
      };
      result.cves.push(cve);
    }
  }
}
