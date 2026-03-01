/**
 * sonobat — Graph type system tests
 *
 * NodeKind/EdgeKind 列挙、Zod props スキーマ、
 * GraphNode/GraphEdge 型、natural key builder のテスト。
 */

import { describe, it, expect } from 'vitest';
import {
  NODE_KINDS,
  EDGE_KINDS,
  HostPropsSchema,
  VhostPropsSchema,
  ServicePropsSchema,
  EndpointPropsSchema,
  InputPropsSchema,
  ObservationPropsSchema,
  CredentialPropsSchema,
  VulnerabilityPropsSchema,
  CvePropsSchema,
  SvcObservationPropsSchema,
  buildNaturalKey,
  validateProps,
  type NodeKind,
  type EdgeKind,
} from '../../src/types/graph.js';

// ============================================================
// NodeKind / EdgeKind 列挙
// ============================================================

describe('NodeKind', () => {
  it('10 種類のノード種別が定義されている', () => {
    expect(NODE_KINDS).toHaveLength(10);
  });

  it('全ノード種別が含まれている', () => {
    const expected: NodeKind[] = [
      'host',
      'vhost',
      'service',
      'endpoint',
      'input',
      'observation',
      'credential',
      'vulnerability',
      'cve',
      'svc_observation',
    ];
    for (const kind of expected) {
      expect(NODE_KINDS).toContain(kind);
    }
  });
});

describe('EdgeKind', () => {
  it('13 種類のエッジ種別が定義されている', () => {
    expect(EDGE_KINDS).toHaveLength(13);
  });

  it('全エッジ種別が含まれている', () => {
    const expected: EdgeKind[] = [
      'HOST_SERVICE',
      'HOST_VHOST',
      'SERVICE_ENDPOINT',
      'SERVICE_INPUT',
      'SERVICE_CREDENTIAL',
      'SERVICE_VULNERABILITY',
      'SERVICE_OBSERVATION',
      'ENDPOINT_INPUT',
      'ENDPOINT_VULNERABILITY',
      'ENDPOINT_CREDENTIAL',
      'INPUT_OBSERVATION',
      'VULNERABILITY_CVE',
      'VHOST_ENDPOINT',
    ];
    for (const kind of expected) {
      expect(EDGE_KINDS).toContain(kind);
    }
  });
});

// ============================================================
// Zod Props スキーマ — 正例
// ============================================================

describe('HostPropsSchema', () => {
  it('正しい props を受け入れる', () => {
    const result = HostPropsSchema.safeParse({
      authorityKind: 'IP',
      authority: '192.168.1.1',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.resolvedIpsJson).toBe('[]');
    }
  });

  it('DOMAIN タイプも受け入れる', () => {
    const result = HostPropsSchema.safeParse({
      authorityKind: 'DOMAIN',
      authority: 'example.com',
      resolvedIpsJson: '["1.2.3.4"]',
    });
    expect(result.success).toBe(true);
  });

  it('authorityKind が不正な場合拒否する', () => {
    const result = HostPropsSchema.safeParse({
      authorityKind: 'INVALID',
      authority: '192.168.1.1',
    });
    expect(result.success).toBe(false);
  });

  it('authority が空の場合拒否する', () => {
    const result = HostPropsSchema.safeParse({
      authorityKind: 'IP',
      authority: '',
    });
    expect(result.success).toBe(false);
  });
});

describe('VhostPropsSchema', () => {
  it('正しい props を受け入れる', () => {
    const result = VhostPropsSchema.safeParse({
      hostname: 'www.example.com',
    });
    expect(result.success).toBe(true);
  });

  it('source がオプションで受け入れられる', () => {
    const result = VhostPropsSchema.safeParse({
      hostname: 'www.example.com',
      source: 'nmap',
    });
    expect(result.success).toBe(true);
  });
});

describe('ServicePropsSchema', () => {
  it('正しい props を受け入れる', () => {
    const result = ServicePropsSchema.safeParse({
      transport: 'tcp',
      port: 80,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
    });
    expect(result.success).toBe(true);
  });

  it('オプションフィールドも受け入れる', () => {
    const result = ServicePropsSchema.safeParse({
      transport: 'tcp',
      port: 443,
      appProto: 'https',
      protoConfidence: 'medium',
      banner: 'nginx/1.21',
      product: 'nginx',
      version: '1.21',
      state: 'open',
    });
    expect(result.success).toBe(true);
  });

  it('port が負数の場合拒否する', () => {
    const result = ServicePropsSchema.safeParse({
      transport: 'tcp',
      port: -1,
      appProto: 'http',
      protoConfidence: 'high',
      state: 'open',
    });
    expect(result.success).toBe(false);
  });
});

describe('EndpointPropsSchema', () => {
  it('正しい props を受け入れる', () => {
    const result = EndpointPropsSchema.safeParse({
      baseUri: 'http://example.com:80',
      method: 'GET',
      path: '/admin',
    });
    expect(result.success).toBe(true);
  });

  it('オプションフィールドも受け入れる', () => {
    const result = EndpointPropsSchema.safeParse({
      baseUri: 'http://example.com:80',
      method: 'POST',
      path: '/login',
      statusCode: 200,
      contentLength: 1234,
      words: 100,
      lines: 50,
    });
    expect(result.success).toBe(true);
  });
});

describe('InputPropsSchema', () => {
  it('正しい props を受け入れる', () => {
    const result = InputPropsSchema.safeParse({
      location: 'query',
      name: 'id',
    });
    expect(result.success).toBe(true);
  });
});

describe('ObservationPropsSchema', () => {
  it('正しい props を受け入れる', () => {
    const result = ObservationPropsSchema.safeParse({
      rawValue: 'test',
      normValue: 'test',
      source: 'ffuf_url',
      confidence: 'high',
      observedAt: '2025-01-01T00:00:00Z',
    });
    expect(result.success).toBe(true);
  });
});

describe('CredentialPropsSchema', () => {
  it('正しい props を受け入れる', () => {
    const result = CredentialPropsSchema.safeParse({
      username: 'admin',
      secret: 'password123',
      secretType: 'password',
      source: 'manual',
      confidence: 'high',
    });
    expect(result.success).toBe(true);
  });
});

describe('VulnerabilityPropsSchema', () => {
  it('正しい props を受け入れる', () => {
    const result = VulnerabilityPropsSchema.safeParse({
      vulnType: 'sqli',
      title: 'SQL Injection in login',
      severity: 'critical',
      confidence: 'high',
      status: 'unverified',
    });
    expect(result.success).toBe(true);
  });

  it('status のデフォルト値が unverified', () => {
    const result = VulnerabilityPropsSchema.safeParse({
      vulnType: 'xss',
      title: 'XSS in search',
      severity: 'medium',
      confidence: 'medium',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status).toBe('unverified');
    }
  });
});

describe('CvePropsSchema', () => {
  it('正しい props を受け入れる', () => {
    const result = CvePropsSchema.safeParse({
      cveId: 'CVE-2021-44228',
    });
    expect(result.success).toBe(true);
  });

  it('オプションフィールドも受け入れる', () => {
    const result = CvePropsSchema.safeParse({
      cveId: 'CVE-2021-44228',
      description: 'Log4Shell',
      cvssScore: 10.0,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
    });
    expect(result.success).toBe(true);
  });
});

describe('SvcObservationPropsSchema', () => {
  it('正しい props を受け入れる', () => {
    const result = SvcObservationPropsSchema.safeParse({
      key: 'os',
      value: 'Linux',
      confidence: 'high',
    });
    expect(result.success).toBe(true);
  });
});

// ============================================================
// validateProps
// ============================================================

describe('validateProps', () => {
  it('正しい kind と props で成功する', () => {
    const result = validateProps('host', {
      authorityKind: 'IP',
      authority: '10.0.0.1',
    });
    expect(result.ok).toBe(true);
  });

  it('不正な props で失敗する', () => {
    const result = validateProps('host', {
      authorityKind: 'INVALID',
    });
    expect(result.ok).toBe(false);
  });

  it('全ノード種別に対応している', () => {
    const propsMap: Record<NodeKind, unknown> = {
      host: { authorityKind: 'IP', authority: '10.0.0.1' },
      vhost: { hostname: 'test.com' },
      service: {
        transport: 'tcp',
        port: 80,
        appProto: 'http',
        protoConfidence: 'high',
        state: 'open',
      },
      endpoint: { baseUri: 'http://test:80', method: 'GET', path: '/' },
      input: { location: 'query', name: 'q' },
      observation: {
        rawValue: 'x',
        normValue: 'x',
        source: 's',
        confidence: 'high',
        observedAt: '2025-01-01T00:00:00Z',
      },
      credential: {
        username: 'u',
        secret: 's',
        secretType: 'password',
        source: 'manual',
        confidence: 'high',
      },
      vulnerability: { vulnType: 'xss', title: 't', severity: 'high', confidence: 'high' },
      cve: { cveId: 'CVE-2021-0001' },
      svc_observation: { key: 'k', value: 'v', confidence: 'high' },
    };

    for (const kind of NODE_KINDS) {
      const result = validateProps(kind, propsMap[kind]);
      expect(result.ok).toBe(true);
    }
  });
});

// ============================================================
// buildNaturalKey
// ============================================================

describe('buildNaturalKey', () => {
  it('host の自然キーを生成する', () => {
    const key = buildNaturalKey('host', { authority: '192.168.1.1' });
    expect(key).toBe('host:192.168.1.1');
  });

  it('vhost の自然キーを生成する (parentId 必須)', () => {
    const key = buildNaturalKey('vhost', { hostname: 'www.example.com' }, 'host-123');
    expect(key).toBe('vhost:host-123:www.example.com');
  });

  it('service の自然キーを生成する (parentId 必須)', () => {
    const key = buildNaturalKey('service', { transport: 'tcp', port: 80 }, 'host-123');
    expect(key).toBe('svc:host-123:tcp:80');
  });

  it('endpoint の自然キーを生成する (parentId 必須)', () => {
    const key = buildNaturalKey('endpoint', { method: 'GET', path: '/admin' }, 'svc-456');
    expect(key).toBe('ep:svc-456:GET:/admin');
  });

  it('input の自然キーを生成する (parentId 必須)', () => {
    const key = buildNaturalKey('input', { location: 'query', name: 'id' }, 'svc-456');
    expect(key).toBe('in:svc-456:query:id');
  });

  it('observation の自然キーは UUID ベース', () => {
    const key = buildNaturalKey('observation', {});
    expect(key).toMatch(/^obs:[0-9a-f-]{36}$/);
  });

  it('credential の自然キーは UUID ベース', () => {
    const key = buildNaturalKey('credential', {});
    expect(key).toMatch(/^cred:[0-9a-f-]{36}$/);
  });

  it('vulnerability の自然キーは UUID ベース', () => {
    const key = buildNaturalKey('vulnerability', {});
    expect(key).toMatch(/^vuln:[0-9a-f-]{36}$/);
  });

  it('cve の自然キーを生成する (parentId 必須)', () => {
    const key = buildNaturalKey('cve', { cveId: 'CVE-2021-44228' }, 'vuln-789');
    expect(key).toBe('cve:vuln-789:CVE-2021-44228');
  });

  it('svc_observation の自然キーは UUID ベース', () => {
    const key = buildNaturalKey('svc_observation', {});
    expect(key).toMatch(/^svcobs:[0-9a-f-]{36}$/);
  });

  it('同じ入力で同じキーが生成される（決定的）', () => {
    const key1 = buildNaturalKey('host', { authority: '10.0.0.1' });
    const key2 = buildNaturalKey('host', { authority: '10.0.0.1' });
    expect(key1).toBe(key2);
  });

  it('異なる入力で異なるキーが生成される', () => {
    const key1 = buildNaturalKey('host', { authority: '10.0.0.1' });
    const key2 = buildNaturalKey('host', { authority: '10.0.0.2' });
    expect(key1).not.toBe(key2);
  });
});
