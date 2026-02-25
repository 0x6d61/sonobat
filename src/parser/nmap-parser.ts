/**
 * sonobat — Nmap XML パーサー
 *
 * nmap の XML 出力を解析し、ParseResult 中間表現を返す。
 * fast-xml-parser を使用して XML をパースする。
 */

import { XMLParser } from 'fast-xml-parser';
import type {
  ParseResult,
  ParsedHost,
  ParsedService,
  ParsedServiceObservation,
} from '../types/parser.js';
import { emptyParseResult } from '../types/parser.js';

// ============================================================
// XML パース後の型定義（unknown から安全に取り出すための構造）
// ============================================================

interface NmapAddress {
  '@_addr': string;
  '@_addrtype': string;
}

interface NmapHostname {
  '@_name': string;
  '@_type': string;
}

interface NmapPortState {
  '@_state': string;
  '@_reason'?: string;
}

interface NmapServiceAttr {
  '@_name'?: string;
  '@_product'?: string;
  '@_version'?: string;
  '@_extrainfo'?: string;
  '@_tunnel'?: string;
  '@_conf'?: string;
}

interface NmapPort {
  '@_protocol': string;
  '@_portid': string;
  state: NmapPortState;
  service?: NmapServiceAttr;
}

interface NmapOsMatch {
  '@_name': string;
  '@_accuracy': string;
}

interface NmapHost {
  address: NmapAddress | NmapAddress[];
  hostnames?: {
    hostname?: NmapHostname | NmapHostname[];
  };
  ports?: {
    port?: NmapPort | NmapPort[];
  };
  os?: {
    osmatch?: NmapOsMatch | NmapOsMatch[];
  };
}

interface NmapRun {
  nmaprun: {
    host?: NmapHost | NmapHost[];
  };
}

// ============================================================
// ユーティリティ
// ============================================================

/** 値を配列に正規化する。undefined/null は空配列を返す。 */
function ensureArray<T>(value: T | T[] | undefined | null): T[] {
  if (value === undefined || value === null) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

/** nmap の conf 属性から protoConfidence を決定する */
function toProtoConfidence(conf: string | undefined): string {
  const n = conf !== undefined ? Number(conf) : 0;
  if (n === 10) return 'high';
  if (n >= 7) return 'medium';
  return 'low';
}

/** OS accuracy から confidence を決定する */
function toOsConfidence(accuracy: string): string {
  const n = Number(accuracy);
  if (n >= 90) return 'high';
  if (n >= 50) return 'medium';
  return 'low';
}

/** サービス名が HTTPS を示すかどうかを判定する */
function isHttps(service: NmapServiceAttr): boolean {
  return service['@_name'] === 'https' || service['@_tunnel'] === 'ssl';
}

/** product, version, extrainfo からバナー文字列を合成する */
function buildBanner(service: NmapServiceAttr): string | undefined {
  const parts: string[] = [];
  if (service['@_product']) parts.push(service['@_product']);
  if (service['@_version']) parts.push(service['@_version']);
  if (service['@_extrainfo']) parts.push(service['@_extrainfo']);
  return parts.length > 0 ? parts.join(' ') : undefined;
}

/** IPv4 アドレスを address 配列から取得する */
function getIpv4Address(addresses: NmapAddress[]): string | undefined {
  const ipv4 = addresses.find((a) => a['@_addrtype'] === 'ipv4');
  return ipv4?.['@_addr'];
}

// ============================================================
// メインパーサー
// ============================================================

/**
 * nmap XML 出力をパースし、ParseResult を返す。
 *
 * @param xml - nmap の XML 出力文字列
 * @returns ParseResult 中間表現
 */
export function parseNmapXml(xml: string): ParseResult {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    allowBooleanAttributes: true,
  });

  const parsed: unknown = parser.parse(xml);
  const nmapRun = parsed as NmapRun;

  const result = emptyParseResult();

  const hosts = ensureArray(nmapRun.nmaprun?.host);

  for (const host of hosts) {
    processHost(host, result);
  }

  return result;
}

/**
 * 単一の host 要素を処理し、結果に追加する。
 */
function processHost(host: NmapHost, result: ParseResult): void {
  // --- ホスト情報 ---
  const addresses = ensureArray(host.address);
  const authority = getIpv4Address(addresses);
  if (authority === undefined) {
    return; // IPv4 アドレスがないホストはスキップ
  }

  const parsedHost: ParsedHost = {
    authority,
    authorityKind: 'IP',
  };
  result.hosts.push(parsedHost);

  // --- サービス情報 ---
  const ports = ensureArray(host.ports?.port);
  const services: ParsedService[] = [];

  for (const port of ports) {
    const service = processPort(port, authority);
    services.push(service);
    result.services.push(service);
  }

  // --- OS 情報 ---
  const osMatches = ensureArray(host.os?.osmatch);
  if (osMatches.length > 0) {
    processOsMatches(osMatches, authority, services, result);
  }
}

/**
 * 単一の port 要素を処理し、ParsedService を返す。
 */
function processPort(port: NmapPort, hostAuthority: string): ParsedService {
  const service = port.service;
  const serviceName = service?.['@_name'] ?? '';

  // appProto の決定: https or tunnel=ssl -> 'https'
  const appProto =
    service !== undefined && isHttps(service) ? 'https' : serviceName;

  const banner = service !== undefined ? buildBanner(service) : undefined;
  const protoConfidence = toProtoConfidence(service?.['@_conf']);

  return {
    hostAuthority,
    transport: port['@_protocol'],
    port: Number(port['@_portid']),
    appProto,
    protoConfidence,
    banner,
    product: service?.['@_product'],
    version: service?.['@_version'],
    state: port.state['@_state'],
  };
}

/**
 * OS マッチ情報を serviceObservations に追加する。
 * 最初のサービスの transport/port を使う。サービスがない場合は port=0, transport='tcp' を使う。
 */
function processOsMatches(
  osMatches: NmapOsMatch[],
  hostAuthority: string,
  services: ParsedService[],
  result: ParseResult,
): void {
  const firstService = services.length > 0 ? services[0] : undefined;
  const transport = firstService?.transport ?? 'tcp';
  const port = firstService?.port ?? 0;

  for (const osMatch of osMatches) {
    const observation: ParsedServiceObservation = {
      hostAuthority,
      transport,
      port,
      key: 'os',
      value: osMatch['@_name'],
      confidence: toOsConfidence(osMatch['@_accuracy']),
    };
    result.serviceObservations.push(observation);
  }
}
