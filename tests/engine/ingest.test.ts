import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../src/db/migrate.js';
import { ingestContent } from '../../src/engine/ingest.js';
import { HostRepository } from '../../src/db/repository/host-repository.js';
import { ArtifactRepository } from '../../src/db/repository/artifact-repository.js';

// ---------------------------------------------------------------------------
// テストデータ
// ---------------------------------------------------------------------------

const NMAP_XML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.41" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>`;

const FFUF_JSON = JSON.stringify({
  commandline: 'ffuf -u http://10.0.0.1:80/FUZZ -w wordlist.txt',
  config: { url: 'http://10.0.0.1:80/FUZZ', method: 'GET' },
  results: [
    {
      input: { FUZZ: 'admin' },
      status: 200,
      length: 1234,
      words: 100,
      lines: 50,
      url: 'http://10.0.0.1:80/admin',
      host: '10.0.0.1',
    },
  ],
});

const NUCLEI_JSONL = `{"template-id":"cve-2021-44228","info":{"name":"Log4Shell RCE","severity":"critical","tags":["rce","cve"],"classification":{"cve-id":["CVE-2021-44228"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cvss-score":10.0}},"type":"http","host":"http://10.0.0.1:80","matched-at":"http://10.0.0.1:80/vulnerable","ip":"10.0.0.1","port":"80","scheme":"http","url":"http://10.0.0.1:80/vulnerable"}`;

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('ingestContent', () => {
  let db: InstanceType<typeof Database>;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
  });

  it('nmap XML をインジェストし、ホストとサービスが作成される', () => {
    const result = ingestContent(db, 'nmap', NMAP_XML, '/tmp/nmap-scan.xml');

    // artifactId が返される
    expect(result.artifactId).toBeDefined();

    // ホストとサービスが作成される
    expect(result.normalizeResult.hostsCreated).toBeGreaterThanOrEqual(1);
    expect(result.normalizeResult.servicesCreated).toBeGreaterThanOrEqual(1);

    // HostRepository でホストが検索できる
    const hostRepo = new HostRepository(db);
    const host = hostRepo.findByAuthority('10.0.0.1');
    expect(host).toBeDefined();
    expect(host!.authority).toBe('10.0.0.1');
  });

  it('ffuf JSON をインジェストし、エンドポイントが作成される', () => {
    const result = ingestContent(db, 'ffuf', FFUF_JSON, '/tmp/ffuf-output.json');

    // エンドポイントが作成される
    expect(result.normalizeResult.httpEndpointsCreated).toBeGreaterThanOrEqual(1);
  });

  it('nuclei JSONL をインジェストし、脆弱性が作成される', () => {
    const result = ingestContent(db, 'nuclei', NUCLEI_JSONL, '/tmp/nuclei-output.jsonl');

    // 脆弱性が作成される
    expect(result.normalizeResult.vulnerabilitiesCreated).toBeGreaterThanOrEqual(1);
  });

  it('Artifact に sha256 が正しく設定される', () => {
    ingestContent(db, 'nmap', NMAP_XML, '/tmp/nmap-scan.xml');

    const expectedSha256 = crypto.createHash('sha256').update(NMAP_XML).digest('hex');
    const artifactRepo = new ArtifactRepository(db);
    const artifacts = artifactRepo.findAll();

    expect(artifacts).toHaveLength(1);
    expect(artifacts[0].sha256).toBe(expectedSha256);
  });

  it('Artifact に tool と kind が正しく設定される', () => {
    ingestContent(db, 'nmap', NMAP_XML, '/tmp/nmap-scan.xml');

    const artifactRepo = new ArtifactRepository(db);
    const artifacts = artifactRepo.findAll();

    expect(artifacts).toHaveLength(1);
    expect(artifacts[0].tool).toBe('nmap');
    expect(artifacts[0].kind).toBe('tool_output');
  });

  it('不明な tool でエラーになる (never 型による網羅性チェック)', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => ingestContent(db, 'unknown' as any, '', '/tmp/unknown.txt')).toThrow();
  });
});
