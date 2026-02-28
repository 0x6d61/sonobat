import { describe, it, expect, beforeAll } from 'vitest';
import { parseNmapXml } from '../../src/parser/nmap-parser.js';
import type { ParseResult } from '../../src/types/parser.js';

// ============================================================
// 共通 XML フィクスチャ
// ============================================================

/** 単一ホスト・3ポート (22/ssh, 80/http, 443/https) + OS + hostname */
const SINGLE_HOST_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p- 10.0.0.1" start="1700000000">
  <host starttime="1700000000" endtime="1700000100">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="example.com" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" conf="10"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.18.0" tunnel="ssl" conf="10"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4" accuracy="95"/>
    </os>
  </host>
</nmaprun>`;

/** 複数ホスト (10.0.0.1: 22/ssh, 10.0.0.2: 80/http + 3306/mysql) */
const MULTI_HOST_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 10.0.0.1 10.0.0.2" start="1700000000">
  <host starttime="1700000000" endtime="1700000050">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.3p1" conf="10"/>
      </port>
    </ports>
  </host>
  <host starttime="1700000000" endtime="1700000060">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.57" conf="10"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" product="MySQL" version="8.0.33" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>`;

/** closed / filtered ポートを含むホスト */
const FILTERED_PORT_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 10.0.0.3" start="1700000000">
  <host starttime="1700000000" endtime="1700000080">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.3" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0" conf="10"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="filtered" reason="no-response"/>
        <service name="http-proxy" conf="3"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="closed" reason="reset"/>
        <service name="microsoft-ds" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>`;

/** ports セクションが無いホスト */
const NO_PORTS_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn 10.0.0.4" start="1700000000">
  <host starttime="1700000000" endtime="1700000020">
    <status state="up" reason="arp-response"/>
    <address addr="10.0.0.4" addrtype="ipv4"/>
  </host>
</nmaprun>`;

// ============================================================
// テスト
// ============================================================

describe('parseNmapXml', () => {
  // ----------------------------------------------------------
  // 1. 単一ホスト・複数ポートをパースする
  // ----------------------------------------------------------
  describe('単一ホスト・複数ポートをパースする', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNmapXml(SINGLE_HOST_XML);
    });

    it('ホストが1件抽出され、authority と authorityKind が正しい', () => {
      expect(result.hosts).toHaveLength(1);
      expect(result.hosts[0]).toMatchObject({
        authority: '10.0.0.1',
        authorityKind: 'IP',
      });
    });

    it('サービスが3件抽出される', () => {
      expect(result.services).toHaveLength(3);
    });

    it('SSH サービスの属性が正しい', () => {
      const ssh = result.services.find((s) => s.port === 22);
      expect(ssh).toBeDefined();
      expect(ssh).toMatchObject({
        hostAuthority: '10.0.0.1',
        transport: 'tcp',
        port: 22,
        appProto: 'ssh',
        product: 'OpenSSH',
        version: '8.9p1',
        state: 'open',
      });
    });

    it('HTTP サービスの属性が正しい', () => {
      const http = result.services.find((s) => s.port === 80);
      expect(http).toBeDefined();
      expect(http).toMatchObject({
        hostAuthority: '10.0.0.1',
        transport: 'tcp',
        port: 80,
        appProto: 'http',
        product: 'nginx',
        version: '1.18.0',
        state: 'open',
      });
    });

    it('HTTPS サービスの属性が正しい', () => {
      const https = result.services.find((s) => s.port === 443);
      expect(https).toBeDefined();
      expect(https).toMatchObject({
        hostAuthority: '10.0.0.1',
        transport: 'tcp',
        port: 443,
        appProto: 'https',
        product: 'nginx',
        version: '1.18.0',
        state: 'open',
      });
    });

    it('全サービスの hostAuthority がホストの authority と一致する', () => {
      for (const svc of result.services) {
        expect(svc.hostAuthority).toBe(result.hosts[0]!.authority);
      }
    });
  });

  // ----------------------------------------------------------
  // 2. サービスの banner を product/version/extrainfo から合成する
  // ----------------------------------------------------------
  describe('サービスの banner を product/version/extrainfo から合成する', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNmapXml(SINGLE_HOST_XML);
    });

    it('SSH サービスの banner に "OpenSSH 8.9p1" が含まれる', () => {
      const ssh = result.services.find((s) => s.port === 22);
      expect(ssh).toBeDefined();
      expect(ssh!.banner).toBeDefined();
      expect(ssh!.banner).toContain('OpenSSH');
      expect(ssh!.banner).toContain('8.9p1');
    });
  });

  // ----------------------------------------------------------
  // 3. OS 情報を serviceObservations として抽出する
  // ----------------------------------------------------------
  describe('OS 情報を serviceObservations として抽出する', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNmapXml(SINGLE_HOST_XML);
    });

    it('serviceObservations に OS 情報が含まれる', () => {
      const osObs = result.serviceObservations.find(
        (o) => o.key === 'os' && o.hostAuthority === '10.0.0.1'
      );
      expect(osObs).toBeDefined();
      expect(osObs).toMatchObject({
        key: 'os',
        value: 'Linux 5.4',
        confidence: 'high',
      });
    });
  });

  // ----------------------------------------------------------
  // 4. hostname を持つホストの authority は IP アドレスになる
  // ----------------------------------------------------------
  describe('hostname を持つホストの resolvedIps を設定する', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNmapXml(SINGLE_HOST_XML);
    });

    it('addr が IP の場合、authority は IP アドレスになる', () => {
      expect(result.hosts).toHaveLength(1);
      expect(result.hosts[0]).toMatchObject({
        authority: '10.0.0.1',
        authorityKind: 'IP',
      });
    });
  });

  // ----------------------------------------------------------
  // 5. 複数ホストをパースする
  // ----------------------------------------------------------
  describe('複数ホストをパースする', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNmapXml(MULTI_HOST_XML);
    });

    it('ホストが2件抽出される', () => {
      expect(result.hosts).toHaveLength(2);
    });

    it('10.0.0.1 と 10.0.0.2 が正しく識別される', () => {
      const authorities = result.hosts.map((h) => h.authority).sort();
      expect(authorities).toEqual(['10.0.0.1', '10.0.0.2']);
    });

    it('10.0.0.1 のサービスは SSH の1件のみ', () => {
      const host1Services = result.services.filter(
        (s) => s.hostAuthority === '10.0.0.1'
      );
      expect(host1Services).toHaveLength(1);
      expect(host1Services[0]).toMatchObject({
        port: 22,
        appProto: 'ssh',
      });
    });

    it('10.0.0.2 のサービスは HTTP と MySQL の2件', () => {
      const host2Services = result.services.filter(
        (s) => s.hostAuthority === '10.0.0.2'
      );
      expect(host2Services).toHaveLength(2);

      const ports = host2Services.map((s) => s.port).sort((a, b) => a - b);
      expect(ports).toEqual([80, 3306]);
    });

    it('サービス合計は3件', () => {
      expect(result.services).toHaveLength(3);
    });
  });

  // ----------------------------------------------------------
  // 6. closed/filtered ポートも含める
  // ----------------------------------------------------------
  describe('closed/filtered ポートも含める', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNmapXml(FILTERED_PORT_XML);
    });

    it('サービスが3件（open, filtered, closed）抽出される', () => {
      expect(result.services).toHaveLength(3);
    });

    it('filtered ポートの state が "filtered" である', () => {
      const filtered = result.services.find((s) => s.port === 8080);
      expect(filtered).toBeDefined();
      expect(filtered!.state).toBe('filtered');
    });

    it('closed ポートの state が "closed" である', () => {
      const closed = result.services.find((s) => s.port === 445);
      expect(closed).toBeDefined();
      expect(closed!.state).toBe('closed');
    });

    it('open ポートの state が "open" である', () => {
      const open = result.services.find((s) => s.port === 80);
      expect(open).toBeDefined();
      expect(open!.state).toBe('open');
    });
  });

  // ----------------------------------------------------------
  // 7. 空の ports セクションを持つホスト
  // ----------------------------------------------------------
  describe('空の ports セクションを持つホスト', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNmapXml(NO_PORTS_XML);
    });

    it('ホストが1件抽出される', () => {
      expect(result.hosts).toHaveLength(1);
      expect(result.hosts[0]).toMatchObject({
        authority: '10.0.0.4',
        authorityKind: 'IP',
      });
    });

    it('サービスは0件（エラーなし）', () => {
      expect(result.services).toHaveLength(0);
    });
  });

  // ----------------------------------------------------------
  // 8. nmap パーサーが生成しないフィールドは空配列
  // ----------------------------------------------------------
  describe('httpEndpoints, inputs, observations, vulnerabilities, cves は空配列', () => {
    let result: ParseResult;

    beforeAll(() => {
      result = parseNmapXml(SINGLE_HOST_XML);
    });

    it('httpEndpoints は空配列', () => {
      expect(result.httpEndpoints).toEqual([]);
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

    it('vulnerabilities は空配列', () => {
      expect(result.vulnerabilities).toEqual([]);
    });

    it('cves は空配列', () => {
      expect(result.cves).toEqual([]);
    });
  });
});
