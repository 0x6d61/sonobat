/**
 * sonobat — ffuf JSON output parser
 *
 * ffuf の JSON 出力をパースし、ParseResult に変換する。
 * パスディスカバリ、パラメータファジングの両方に対応。
 */

import type {
  ParseResult,
  ParsedHost,
  ParsedService,
  ParsedHttpEndpoint,
  ParsedInput,
  ParsedEndpointInput,
  ParsedObservation,
} from '../types/parser.js';
import { emptyParseResult } from '../types/parser.js';

// ---------------------------------------------------------------------------
// 内部型: ffuf JSON 構造のバリデーション用
// ---------------------------------------------------------------------------

interface FfufConfig {
  url: string;
  method: string;
}

interface FfufResult {
  input: Record<string, string>;
  status: number;
  length: number;
  words: number;
  lines: number;
  url: string;
  host: string;
}

interface FfufJson {
  commandline: string;
  config: FfufConfig;
  results: FfufResult[];
}

// ---------------------------------------------------------------------------
// バリデーション
// ---------------------------------------------------------------------------

const IP_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validateFfufJson(raw: unknown): FfufJson {
  if (!isRecord(raw)) {
    throw new Error('ffuf JSON: root must be an object');
  }

  if (typeof raw['commandline'] !== 'string') {
    throw new Error('ffuf JSON: commandline must be a string');
  }

  const config = raw['config'];
  if (!isRecord(config)) {
    throw new Error('ffuf JSON: config must be an object');
  }
  if (typeof config['url'] !== 'string' || typeof config['method'] !== 'string') {
    throw new Error('ffuf JSON: config.url and config.method must be strings');
  }

  if (!Array.isArray(raw['results'])) {
    throw new Error('ffuf JSON: results must be an array');
  }

  const results: FfufResult[] = [];
  for (const item of raw['results'] as unknown[]) {
    if (!isRecord(item)) {
      throw new Error('ffuf JSON: each result must be an object');
    }
    results.push({
      input: isRecord(item['input'])
        ? Object.fromEntries(
            Object.entries(item['input'] as Record<string, unknown>).map(([k, v]) => [
              k,
              String(v),
            ]),
          )
        : {},
      status: typeof item['status'] === 'number' ? item['status'] : 0,
      length: typeof item['length'] === 'number' ? item['length'] : 0,
      words: typeof item['words'] === 'number' ? item['words'] : 0,
      lines: typeof item['lines'] === 'number' ? item['lines'] : 0,
      url: typeof item['url'] === 'string' ? item['url'] : '',
      host: typeof item['host'] === 'string' ? item['host'] : '',
    });
  }

  return {
    commandline: raw['commandline'] as string,
    config: {
      url: config['url'] as string,
      method: config['method'] as string,
    },
    results,
  };
}

// ---------------------------------------------------------------------------
// URL ユーティリティ
// ---------------------------------------------------------------------------

interface ParsedUrl {
  scheme: string;
  hostname: string;
  port: number;
  pathname: string;
  searchParams: URLSearchParams;
}

function parseUrl(urlStr: string): ParsedUrl {
  const parsed = new URL(urlStr);
  const scheme = parsed.protocol.replace(':', '');

  let port: number;
  if (parsed.port !== '') {
    port = Number(parsed.port);
  } else {
    port = scheme === 'https' ? 443 : 80;
  }

  return {
    scheme,
    hostname: parsed.hostname,
    port,
    pathname: parsed.pathname,
    searchParams: parsed.searchParams,
  };
}

function determineAuthorityKind(hostname: string): 'IP' | 'DOMAIN' {
  return IP_REGEX.test(hostname) ? 'IP' : 'DOMAIN';
}

// ---------------------------------------------------------------------------
// メインパーサー
// ---------------------------------------------------------------------------

/**
 * ffuf の JSON 出力文字列をパースし、ParseResult を返す。
 *
 * @param jsonContent - ffuf が `-of json` で出力した JSON 文字列
 * @returns ParseResult
 */
export function parseFfufJson(jsonContent: string): ParseResult {
  const raw: unknown = JSON.parse(jsonContent);
  const ffuf = validateFfufJson(raw);
  const method = ffuf.config.method;

  // results が空なら全て空配列
  if (ffuf.results.length === 0) {
    return emptyParseResult();
  }

  // ----- 集約用 Map -----
  // hosts: authority -> ParsedHost
  const hostsMap = new Map<string, ParsedHost>();
  // services: "authority:port" -> ParsedService
  const servicesMap = new Map<string, ParsedService>();
  // httpEndpoints: "method:path" -> ParsedHttpEndpoint
  const endpointsMap = new Map<string, ParsedHttpEndpoint>();
  // inputs: "name" -> ParsedInput (クエリパラメータ名で重複排除)
  const inputsMap = new Map<string, ParsedInput>();
  // endpointInputs: "method:path:location:name" -> ParsedEndpointInput
  const endpointInputsMap = new Map<string, ParsedEndpointInput>();
  // observations: "location:name:rawValue" -> ParsedObservation
  const observationsMap = new Map<string, ParsedObservation>();

  for (const result of ffuf.results) {
    if (result.url === '') {
      continue;
    }

    const parsed = parseUrl(result.url);
    const { scheme, hostname, port, pathname, searchParams } = parsed;
    const authorityKind = determineAuthorityKind(hostname);
    const baseUri = `${scheme}://${hostname}:${port}`;

    // --- Host ---
    if (!hostsMap.has(hostname)) {
      hostsMap.set(hostname, {
        authority: hostname,
        authorityKind,
      });
    }

    // --- Service ---
    const serviceKey = `${hostname}:${port}`;
    if (!servicesMap.has(serviceKey)) {
      servicesMap.set(serviceKey, {
        hostAuthority: hostname,
        transport: 'tcp',
        port,
        appProto: scheme,
        protoConfidence: 'high',
        state: 'open',
      });
    }

    // --- HTTP Endpoint (method + path で重複排除) ---
    const endpointKey = `${method}:${pathname}`;
    if (!endpointsMap.has(endpointKey)) {
      endpointsMap.set(endpointKey, {
        hostAuthority: hostname,
        port,
        baseUri,
        method,
        path: pathname,
        statusCode: result.status,
        contentLength: result.length,
        words: result.words,
        lines: result.lines,
      });
    }

    // --- Query Parameters -> inputs, observations, endpointInputs ---
    for (const [paramName, paramValue] of searchParams.entries()) {
      // Input (パラメータ名で重複排除)
      if (!inputsMap.has(paramName)) {
        inputsMap.set(paramName, {
          hostAuthority: hostname,
          port,
          location: 'query',
          name: paramName,
        });
      }

      // EndpointInput (endpoint + input の組み合わせで重複排除)
      const eiKey = `${method}:${pathname}:query:${paramName}`;
      if (!endpointInputsMap.has(eiKey)) {
        endpointInputsMap.set(eiKey, {
          hostAuthority: hostname,
          port,
          method,
          path: pathname,
          inputLocation: 'query',
          inputName: paramName,
        });
      }

      // Observation (パラメータ名 + 値で重複排除)
      const obsKey = `query:${paramName}:${paramValue}`;
      if (!observationsMap.has(obsKey)) {
        observationsMap.set(obsKey, {
          hostAuthority: hostname,
          port,
          inputLocation: 'query',
          inputName: paramName,
          rawValue: paramValue,
          normValue: paramValue,
          source: 'ffuf_url',
          confidence: 'high',
        });
      }
    }
  }

  return {
    hosts: [...hostsMap.values()],
    services: [...servicesMap.values()],
    serviceObservations: [],
    httpEndpoints: [...endpointsMap.values()],
    inputs: [...inputsMap.values()],
    endpointInputs: [...endpointInputsMap.values()],
    observations: [...observationsMap.values()],
    vulnerabilities: [],
    cves: [],
  };
}
