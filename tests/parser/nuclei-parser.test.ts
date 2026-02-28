import { describe, it, expect, beforeAll } from 'vitest';
import { parseNucleiJsonl } from '../../src/parser/nuclei-parser.js';
import type { ParseResult } from '../../src/types/parser.js';

// ============================================================
// 共通 JSONL フィクスチャ
// ============================================================

/** CVE-2021-41773 Apache Path Traversal (critical) */
const CVE_FINDING_LINE = JSON.stringify({
  'template-id': 'cve-2021-41773',
  info: {
    name: 'Apache HTTP Server Path Traversal',
    severity: 'critical',
    tags: ['cve', 'apache', 'lfi'],
    classification: {
      'cve-id': ['CVE-2021-41773'],
      'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      'cvss-score': 7.5,
    },
  },
  type: 'http',
  host: 'http://10.0.0.2:8080',
  'matched-at': 'http://10.0.0.2:8080/icons/.%2e/%2e%2e/%2e%2e/etc/passwd',
  ip: '10.0.0.2',
  port: '8080',
  scheme: 'http',
  url: 'http://10.0.0.2:8080/icons/.%2e/%2e%2e/%2e%2e/etc/passwd',
  timestamp: '2024-01-15T10:31:00.000Z',
  'matcher-name': '',
  'matched-line': 'root:x:0:0:root:/root:/bin/bash',
  'extracted-results': ['root:x:0:0:root:/root:/bin/bash'],
});

/** Nginx Detection (info severity / tech detect) */
const TECH_DETECT_LINE = JSON.stringify({
  'template-id': 'tech-detect',
  info: {
    name: 'Nginx Detection',
    severity: 'info',
    tags: ['tech', 'nginx'],
    classification: {},
  },
  type: 'http',
  host: 'http://10.0.0.1:80',
  'matched-at': 'http://10.0.0.1:80/',
  ip: '10.0.0.1',
  port: '80',
  scheme: 'http',
  url: 'http://10.0.0.1:80/',
  timestamp: '2024-01-15T10:30:00.000Z',
  'matcher-name': 'nginx',
  'matched-line': '',
  'extracted-results': ['nginx/1.18.0'],
});

/** HTTPS + port 443 の finding */
const HTTPS_FINDING_LINE = JSON.stringify({
  'template-id': 'ssl-detect',
  info: {
    name: 'SSL/TLS Detection',
    severity: 'info',
    tags: ['tech', 'ssl'],
    classification: {},
  },
  type: 'http',
  host: 'https://10.0.0.5:443',
  'matched-at': 'https://10.0.0.5:443/',
  ip: '10.0.0.5',
  port: '443',
  scheme: 'https',
  url: 'https://10.0.0.5:443/',
  timestamp: '2024-01-15T10:35:00.000Z',
  'matcher-name': 'tls',
  'matched-line': '',
  'extracted-results': [],
});

/** SQLi 検出 finding */
const SQLI_FINDING_LINE = JSON.stringify({
  'template-id': 'generic-sqli',
  info: {
    name: 'SQL Injection Detected',
    severity: 'high',
    tags: ['sqli', 'injection'],
    classification: {},
  },
  type: 'http',
  host: 'http://10.0.0.10:80',
  'matched-at': "http://10.0.0.10:80/search?q=test'%20OR%201=1",
  ip: '10.0.0.10',
  port: '80',
  scheme: 'http',
  url: "http://10.0.0.10:80/search?q=test'%20OR%201=1",
  timestamp: '2024-01-15T10:40:00.000Z',
  'matcher-name': 'error-based',
  'matched-line': '',
  'extracted-results': [],
});

/** XSS 検出 finding */
const XSS_FINDING_LINE = JSON.stringify({
  'template-id': 'generic-xss',
  info: {
    name: 'Cross-Site Scripting Detected',
    severity: 'medium',
    tags: ['xss', 'injection'],
    classification: {},
  },
  type: 'http',
  host: 'http://10.0.0.10:80',
  'matched-at': 'http://10.0.0.10:80/comment?body=<script>alert(1)</script>',
  ip: '10.0.0.10',
  port: '80',
  scheme: 'http',
  url: 'http://10.0.0.10:80/comment?body=<script>alert(1)</script>',
  timestamp: '2024-01-15T10:41:00.000Z',
  'matcher-name': '',
  'matched-line': '',
  'extracted-results': [],
});

/** low severity finding */
const LOW_FINDING_LINE = JSON.stringify({
  'template-id': 'missing-headers',
  info: {
    name: 'Missing Security Headers',
    severity: 'low',
    tags: ['misconfiguration'],
    classification: {},
  },
  type: 'http',
  host: 'http://10.0.0.10:80',
  'matched-at': 'http://10.0.0.10:80/',
  ip: '10.0.0.10',
  port: '80',
  scheme: 'http',
  url: 'http://10.0.0.10:80/',
  timestamp: '2024-01-15T10:42:00.000Z',
  'matcher-name': '',
  'matched-line': '',
  'extracted-results': [],
});

/** CVE のみのタグを持つ finding（具体的な vulnType なし） */
const CVE_ONLY_TAG_LINE = JSON.stringify({
  'template-id': 'cve-2023-12345',
  info: {
    name: 'Some CVE Vulnerability',
    severity: 'high',
    tags: ['cve'],
    classification: {
      'cve-id': ['CVE-2023-12345'],
      'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
      'cvss-score': 6.1,
    },
  },
  type: 'http',
  host: 'http://10.0.0.20:80',
  'matched-at': 'http://10.0.0.20:80/api/v1',
  ip: '10.0.0.20',
  port: '80',
  scheme: 'http',
  url: 'http://10.0.0.20:80/api/v1',
  timestamp: '2024-01-15T10:45:00.000Z',
  'matcher-name': '',
  'matched-line': '',
  'extracted-results': [],
});

// ============================================================
// テスト
// ============================================================

describe('parseNucleiJsonl', () => {
  // ----------------------------------------------------------
  // 1. 脆弱性検出結果をパースする
  // ----------------------------------------------------------
  describe('脆弱性検出結果をパースする', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNucleiJsonl(CVE_FINDING_LINE);
    });

    it('ホストが1件抽出され、authority と authorityKind が正しい', () => {
      expect(result.hosts).toHaveLength(1);
      expect(result.hosts[0]).toMatchObject({
        authority: '10.0.0.2',
        authorityKind: 'IP',
      });
    });

    it('サービスが1件抽出され、属性が正しい', () => {
      expect(result.services).toHaveLength(1);
      expect(result.services[0]).toMatchObject({
        hostAuthority: '10.0.0.2',
        port: 8080,
        appProto: 'http',
        transport: 'tcp',
      });
    });

    it('脆弱性が1件抽出され、属性が正しい', () => {
      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.vulnerabilities[0]).toMatchObject({
        vulnType: 'lfi',
        title: 'Apache HTTP Server Path Traversal',
        severity: 'critical',
      });
    });

    it('CVE が1件抽出される', () => {
      expect(result.cves).toHaveLength(1);
      expect(result.cves[0]).toMatchObject({
        cveId: 'CVE-2021-41773',
        cvssScore: 7.5,
      });
    });
  });

  // ----------------------------------------------------------
  // 2. info severity の検出結果（tech detect）もパースする
  // ----------------------------------------------------------
  describe('info severity の検出結果（tech detect）もパースする', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNucleiJsonl(TECH_DETECT_LINE);
    });

    it('ホストが1件抽出される', () => {
      expect(result.hosts).toHaveLength(1);
      expect(result.hosts[0]).toMatchObject({
        authority: '10.0.0.1',
        authorityKind: 'IP',
      });
    });

    it('サービスが1件抽出される', () => {
      expect(result.services).toHaveLength(1);
      expect(result.services[0]).toMatchObject({
        hostAuthority: '10.0.0.1',
        port: 80,
        appProto: 'http',
        transport: 'tcp',
      });
    });

    it('脆弱性が1件抽出され、severity が info である', () => {
      expect(result.vulnerabilities).toHaveLength(1);
      expect(result.vulnerabilities[0]).toMatchObject({
        severity: 'info',
      });
    });
  });

  // ----------------------------------------------------------
  // 3. 複数行の JSONL をパースする
  // ----------------------------------------------------------
  describe('複数行の JSONL をパースする', () => {
    let result: ParseResult;

    beforeAll(() => {
      const jsonl = [TECH_DETECT_LINE, CVE_FINDING_LINE].join('\n');
      result = parseNucleiJsonl(jsonl);
    });

    it('ホストが2件抽出される', () => {
      expect(result.hosts).toHaveLength(2);
      const authorities = result.hosts.map((h) => h.authority).sort();
      expect(authorities).toEqual(['10.0.0.1', '10.0.0.2']);
    });

    it('サービスが2件抽出される', () => {
      expect(result.services).toHaveLength(2);
    });

    it('脆弱性が2件抽出される', () => {
      expect(result.vulnerabilities).toHaveLength(2);
    });

    it('CVE は1件のみ（CVE finding のみ classification を持つ）', () => {
      expect(result.cves).toHaveLength(1);
      expect(result.cves[0]).toMatchObject({
        cveId: 'CVE-2021-41773',
      });
    });
  });

  // ----------------------------------------------------------
  // 4. CVE 情報を正しく抽出する
  // ----------------------------------------------------------
  describe('CVE 情報を正しく抽出する', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNucleiJsonl(CVE_FINDING_LINE);
    });

    it('cveId が CVE-2021-41773 である', () => {
      expect(result.cves).toHaveLength(1);
      expect(result.cves[0]!.cveId).toBe('CVE-2021-41773');
    });

    it('cvssScore が 7.5 である', () => {
      expect(result.cves[0]!.cvssScore).toBe(7.5);
    });

    it('cvssVector に CVSS:3.1 が含まれる', () => {
      expect(result.cves[0]!.cvssVector).toBeDefined();
      expect(result.cves[0]!.cvssVector).toContain('CVSS:3.1');
    });

    it('vulnerabilityTitle が脆弱性の title と一致する', () => {
      expect(result.cves[0]!.vulnerabilityTitle).toBe('Apache HTTP Server Path Traversal');
    });
  });

  // ----------------------------------------------------------
  // 5. matched-at URL から http_endpoint を生成する
  // ----------------------------------------------------------
  describe('matched-at URL から http_endpoint を生成する', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNucleiJsonl(CVE_FINDING_LINE);
    });

    it('httpEndpoints が1件生成される', () => {
      expect(result.httpEndpoints).toHaveLength(1);
    });

    it('path が matched-at URL のパス部分と一致する', () => {
      expect(result.httpEndpoints[0]!.path).toBe('/icons/.%2e/%2e%2e/%2e%2e/etc/passwd');
    });

    it('hostAuthority と port が正しい', () => {
      expect(result.httpEndpoints[0]).toMatchObject({
        hostAuthority: '10.0.0.2',
        port: 8080,
      });
    });

    it('baseUri が正しい', () => {
      expect(result.httpEndpoints[0]!.baseUri).toBe('http://10.0.0.2:8080');
    });
  });

  // ----------------------------------------------------------
  // 6. severity マッピング
  // ----------------------------------------------------------
  describe('severity マッピング', () => {
    it('info severity が正しくマッピングされる', () => {
      const result = parseNucleiJsonl(TECH_DETECT_LINE);
      expect(result.vulnerabilities[0]!.severity).toBe('info');
    });

    it('low severity が正しくマッピングされる', () => {
      const result = parseNucleiJsonl(LOW_FINDING_LINE);
      expect(result.vulnerabilities[0]!.severity).toBe('low');
    });

    it('medium severity が正しくマッピングされる', () => {
      const result = parseNucleiJsonl(XSS_FINDING_LINE);
      expect(result.vulnerabilities[0]!.severity).toBe('medium');
    });

    it('high severity が正しくマッピングされる', () => {
      const result = parseNucleiJsonl(SQLI_FINDING_LINE);
      expect(result.vulnerabilities[0]!.severity).toBe('high');
    });

    it('critical severity が正しくマッピングされる', () => {
      const result = parseNucleiJsonl(CVE_FINDING_LINE);
      expect(result.vulnerabilities[0]!.severity).toBe('critical');
    });
  });

  // ----------------------------------------------------------
  // 7. vulnType の推定
  // ----------------------------------------------------------
  describe('vulnType の推定', () => {
    it('tags に sqli を含む場合、vulnType が sqli になる', () => {
      const result = parseNucleiJsonl(SQLI_FINDING_LINE);
      expect(result.vulnerabilities[0]!.vulnType).toBe('sqli');
    });

    it('tags に xss を含む場合、vulnType が xss になる', () => {
      const result = parseNucleiJsonl(XSS_FINDING_LINE);
      expect(result.vulnerabilities[0]!.vulnType).toBe('xss');
    });

    it('tags に lfi を含む場合、vulnType が lfi になる', () => {
      const result = parseNucleiJsonl(CVE_FINDING_LINE);
      expect(result.vulnerabilities[0]!.vulnType).toBe('lfi');
    });

    it('tags に cve のみの場合、vulnType が other になる', () => {
      const result = parseNucleiJsonl(CVE_ONLY_TAG_LINE);
      expect(result.vulnerabilities[0]!.vulnType).toBe('other');
    });
  });

  // ----------------------------------------------------------
  // 8. 空の JSONL / 空行を含む JSONL
  // ----------------------------------------------------------
  describe('空の JSONL / 空行を含む JSONL', () => {
    it('空文字列は空の ParseResult を返す', () => {
      const result = parseNucleiJsonl('');

      expect(result.hosts).toEqual([]);
      expect(result.services).toEqual([]);
      expect(result.httpEndpoints).toEqual([]);
      expect(result.vulnerabilities).toEqual([]);
      expect(result.cves).toEqual([]);
    });

    it('空行を含む JSONL を正常にパースする', () => {
      const jsonl = [TECH_DETECT_LINE, '', '  ', CVE_FINDING_LINE, ''].join('\n');
      const result = parseNucleiJsonl(jsonl);

      expect(result.hosts).toHaveLength(2);
      expect(result.vulnerabilities).toHaveLength(2);
    });
  });

  // ----------------------------------------------------------
  // 9. HTTPS スキームの処理
  // ----------------------------------------------------------
  describe('HTTPS スキームの処理', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNucleiJsonl(HTTPS_FINDING_LINE);
    });

    it('サービスの appProto が https になる', () => {
      expect(result.services).toHaveLength(1);
      expect(result.services[0]!.appProto).toBe('https');
    });

    it('httpEndpoints の baseUri が https:// を含む', () => {
      expect(result.httpEndpoints).toHaveLength(1);
      expect(result.httpEndpoints[0]!.baseUri).toContain('https://');
    });

    it('ホストの authority が正しい', () => {
      expect(result.hosts).toHaveLength(1);
      expect(result.hosts[0]!.authority).toBe('10.0.0.5');
    });

    it('サービスの port が 443 になる', () => {
      expect(result.services[0]!.port).toBe(443);
    });
  });

  // ----------------------------------------------------------
  // 10. inputs, observations, serviceObservations は空配列
  // ----------------------------------------------------------
  describe('inputs, observations, serviceObservations は空配列', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNucleiJsonl(CVE_FINDING_LINE);
    });

    it('inputs は空配列', () => {
      expect(result.inputs).toEqual([]);
    });

    it('endpointInputs は空配列', () => {
      expect(result.endpointInputs).toEqual([]);
    });

    it('observations は空配列', () => {
      expect(result.observations).toEqual([]);
    });

    it('serviceObservations は空配列', () => {
      expect(result.serviceObservations).toEqual([]);
    });
  });
});
