import { parseFfufJson } from '../../src/parser/ffuf-parser.js';

// ---------------------------------------------------------------------------
// ヘルパー: リアルな ffuf JSON 出力を生成
// ---------------------------------------------------------------------------

function buildFfufJson(overrides: {
  commandline?: string;
  url?: string;
  method?: string;
  results?: Record<string, unknown>[];
}): string {
  const {
    commandline = 'ffuf -u http://10.0.0.1:80/FUZZ -w wordlist.txt -o output.json -of json',
    url = 'http://10.0.0.1:80/FUZZ',
    method = 'GET',
    results = [],
  } = overrides;

  return JSON.stringify({
    commandline,
    config: { url, method },
    results,
  });
}

function buildResult(overrides: Partial<{
  input: Record<string, string>;
  position: number;
  status: number;
  length: number;
  words: number;
  lines: number;
  'content-type': string;
  redirectlocation: string;
  resultfile: string;
  url: string;
  host: string;
}>): Record<string, unknown> {
  return {
    input: { FUZZ: 'test' },
    position: 1,
    status: 200,
    length: 1234,
    words: 100,
    lines: 50,
    'content-type': 'text/html',
    redirectlocation: '',
    resultfile: '',
    url: 'http://10.0.0.1:80/test',
    host: '10.0.0.1:80',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('parseFfufJson', () => {
  // -----------------------------------------------------------------------
  // 1. パスディスカバリ結果をパースする
  // -----------------------------------------------------------------------
  it('パスディスカバリ結果をパースする', () => {
    const json = buildFfufJson({
      commandline: 'ffuf -u http://10.0.0.1:80/FUZZ -w wordlist.txt -o output.json -of json',
      url: 'http://10.0.0.1:80/FUZZ',
      method: 'GET',
      results: [
        buildResult({
          input: { FUZZ: 'admin' },
          position: 1,
          status: 200,
          length: 1234,
          words: 100,
          lines: 50,
          'content-type': 'text/html',
          redirectlocation: '',
          url: 'http://10.0.0.1:80/admin',
          host: '10.0.0.1:80',
        }),
        buildResult({
          input: { FUZZ: 'login' },
          position: 2,
          status: 302,
          length: 0,
          words: 0,
          lines: 0,
          'content-type': '',
          redirectlocation: '/dashboard',
          url: 'http://10.0.0.1:80/login',
          host: '10.0.0.1:80',
        }),
      ],
    });

    const result = parseFfufJson(json);

    // ホスト: 1 件（IP アドレス）
    expect(result.hosts).toHaveLength(1);
    expect(result.hosts[0]).toMatchObject({
      authority: '10.0.0.1',
      authorityKind: 'IP',
    });

    // サービス: 1 件（HTTP on port 80）
    expect(result.services).toHaveLength(1);
    expect(result.services[0]).toMatchObject({
      hostAuthority: '10.0.0.1',
      port: 80,
      appProto: 'http',
      transport: 'tcp',
    });

    // HTTP エンドポイント: 2 件
    expect(result.httpEndpoints).toHaveLength(2);

    const adminEndpoint = result.httpEndpoints.find((e) => e.path === '/admin');
    expect(adminEndpoint).toBeDefined();
    expect(adminEndpoint).toMatchObject({
      hostAuthority: '10.0.0.1',
      port: 80,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/admin',
      statusCode: 200,
      contentLength: 1234,
      words: 100,
      lines: 50,
    });

    const loginEndpoint = result.httpEndpoints.find((e) => e.path === '/login');
    expect(loginEndpoint).toBeDefined();
    expect(loginEndpoint).toMatchObject({
      hostAuthority: '10.0.0.1',
      port: 80,
      baseUri: 'http://10.0.0.1:80',
      method: 'GET',
      path: '/login',
      statusCode: 302,
      contentLength: 0,
      words: 0,
      lines: 0,
    });
  });

  // -----------------------------------------------------------------------
  // 2. URL のクエリパラメータを inputs に変換する
  // -----------------------------------------------------------------------
  it('URL のクエリパラメータを inputs に変換する', () => {
    const json = buildFfufJson({
      commandline: 'ffuf -u "http://10.0.0.1:80/search?q=FUZZ" -w wordlist.txt -o output.json -of json',
      url: 'http://10.0.0.1:80/search?q=FUZZ',
      method: 'GET',
      results: [
        buildResult({
          input: { FUZZ: 'admin' },
          position: 1,
          status: 200,
          length: 512,
          words: 45,
          lines: 12,
          'content-type': 'text/html',
          url: 'http://10.0.0.1:80/search?q=admin',
          host: '10.0.0.1:80',
        }),
        buildResult({
          input: { FUZZ: 'test' },
          position: 2,
          status: 200,
          length: 256,
          words: 22,
          lines: 8,
          'content-type': 'text/html',
          url: 'http://10.0.0.1:80/search?q=test',
          host: '10.0.0.1:80',
        }),
      ],
    });

    const result = parseFfufJson(json);

    // 入力パラメータ: 1 件（q）
    expect(result.inputs).toHaveLength(1);
    expect(result.inputs[0]).toMatchObject({
      hostAuthority: '10.0.0.1',
      port: 80,
      location: 'query',
      name: 'q',
    });

    // 観測値: 2 件（admin, test）
    expect(result.observations).toHaveLength(2);
    const adminObs = result.observations.find((o) => o.rawValue === 'admin');
    expect(adminObs).toBeDefined();
    expect(adminObs).toMatchObject({
      hostAuthority: '10.0.0.1',
      port: 80,
      inputLocation: 'query',
      inputName: 'q',
      rawValue: 'admin',
    });

    const testObs = result.observations.find((o) => o.rawValue === 'test');
    expect(testObs).toBeDefined();
    expect(testObs).toMatchObject({
      hostAuthority: '10.0.0.1',
      port: 80,
      inputLocation: 'query',
      inputName: 'q',
      rawValue: 'test',
    });

    // エンドポイント ↔ 入力の紐づけ: endpoint_inputs
    expect(result.endpointInputs).toHaveLength(1);
    expect(result.endpointInputs[0]).toMatchObject({
      hostAuthority: '10.0.0.1',
      port: 80,
      method: 'GET',
      path: '/search',
      inputLocation: 'query',
      inputName: 'q',
    });
  });

  // -----------------------------------------------------------------------
  // 3. HTTPS URL を正しく処理する
  // -----------------------------------------------------------------------
  it('HTTPS URL を正しく処理する', () => {
    const json = buildFfufJson({
      commandline: 'ffuf -u https://example.com:443/FUZZ -w wordlist.txt -o output.json -of json',
      url: 'https://example.com:443/FUZZ',
      method: 'GET',
      results: [
        buildResult({
          input: { FUZZ: 'api' },
          position: 1,
          status: 200,
          length: 2048,
          words: 150,
          lines: 30,
          'content-type': 'application/json',
          url: 'https://example.com:443/api',
          host: 'example.com:443',
        }),
      ],
    });

    const result = parseFfufJson(json);

    // ホスト: ドメイン名
    expect(result.hosts).toHaveLength(1);
    expect(result.hosts[0]).toMatchObject({
      authority: 'example.com',
      authorityKind: 'DOMAIN',
    });

    // サービス: HTTPS on port 443
    expect(result.services).toHaveLength(1);
    expect(result.services[0]).toMatchObject({
      hostAuthority: 'example.com',
      port: 443,
      appProto: 'https',
      transport: 'tcp',
    });

    // baseUri に HTTPS スキームが含まれる
    expect(result.httpEndpoints).toHaveLength(1);
    expect(result.httpEndpoints[0]).toMatchObject({
      baseUri: 'https://example.com:443',
    });
  });

  // -----------------------------------------------------------------------
  // 4. POST リクエストのファジング結果をパースする
  // -----------------------------------------------------------------------
  it('POST リクエストのファジング結果をパースする', () => {
    const json = buildFfufJson({
      commandline: 'ffuf -u http://10.0.0.1:80/api/login -X POST -d "username=FUZZ" -w wordlist.txt -o output.json -of json',
      url: 'http://10.0.0.1:80/api/login',
      method: 'POST',
      results: [
        buildResult({
          input: { FUZZ: 'admin' },
          position: 1,
          status: 200,
          length: 64,
          words: 5,
          lines: 1,
          'content-type': 'application/json',
          url: 'http://10.0.0.1:80/api/login',
          host: '10.0.0.1:80',
        }),
        buildResult({
          input: { FUZZ: 'root' },
          position: 2,
          status: 403,
          length: 32,
          words: 3,
          lines: 1,
          'content-type': 'application/json',
          url: 'http://10.0.0.1:80/api/login',
          host: '10.0.0.1:80',
        }),
      ],
    });

    const result = parseFfufJson(json);

    // すべてのエンドポイントが POST メソッド
    expect(result.httpEndpoints.length).toBeGreaterThanOrEqual(1);
    for (const endpoint of result.httpEndpoints) {
      expect(endpoint.method).toBe('POST');
    }
  });

  // -----------------------------------------------------------------------
  // 5. 複数のクエリパラメータを持つ URL
  // -----------------------------------------------------------------------
  it('複数のクエリパラメータを持つ URL を処理する', () => {
    const json = buildFfufJson({
      commandline: 'ffuf -u "http://10.0.0.1:80/api?user=FUZZ&role=admin" -w wordlist.txt -o output.json -of json',
      url: 'http://10.0.0.1:80/api?user=FUZZ&role=admin',
      method: 'GET',
      results: [
        buildResult({
          input: { FUZZ: 'john' },
          position: 1,
          status: 200,
          length: 768,
          words: 60,
          lines: 15,
          'content-type': 'application/json',
          url: 'http://10.0.0.1:80/api?user=john&role=admin',
          host: '10.0.0.1:80',
        }),
      ],
    });

    const result = parseFfufJson(json);

    // 入力パラメータ: 2 件（user, role）
    expect(result.inputs).toHaveLength(2);

    const userInput = result.inputs.find((i) => i.name === 'user');
    expect(userInput).toBeDefined();
    expect(userInput).toMatchObject({
      hostAuthority: '10.0.0.1',
      port: 80,
      location: 'query',
      name: 'user',
    });

    const roleInput = result.inputs.find((i) => i.name === 'role');
    expect(roleInput).toBeDefined();
    expect(roleInput).toMatchObject({
      hostAuthority: '10.0.0.1',
      port: 80,
      location: 'query',
      name: 'role',
    });

    // 両方の入力に対して観測値が存在する
    const userObs = result.observations.filter((o) => o.inputName === 'user');
    expect(userObs.length).toBeGreaterThanOrEqual(1);
    expect(userObs[0]).toMatchObject({
      inputLocation: 'query',
      inputName: 'user',
      rawValue: 'john',
    });

    const roleObs = result.observations.filter((o) => o.inputName === 'role');
    expect(roleObs.length).toBeGreaterThanOrEqual(1);
    expect(roleObs[0]).toMatchObject({
      inputLocation: 'query',
      inputName: 'role',
      rawValue: 'admin',
    });
  });

  // -----------------------------------------------------------------------
  // 6. 空の results 配列
  // -----------------------------------------------------------------------
  it('空の results 配列を処理する', () => {
    const json = buildFfufJson({
      commandline: 'ffuf -u http://10.0.0.1:80/FUZZ -w wordlist.txt -o output.json -of json',
      url: 'http://10.0.0.1:80/FUZZ',
      method: 'GET',
      results: [],
    });

    const result = parseFfufJson(json);

    // results が空 = 発見データなし → すべて空配列
    expect(result.hosts).toHaveLength(0);
    expect(result.services).toHaveLength(0);
    expect(result.httpEndpoints).toHaveLength(0);
    expect(result.inputs).toHaveLength(0);
    expect(result.endpointInputs).toHaveLength(0);
    expect(result.observations).toHaveLength(0);
    expect(result.serviceObservations).toHaveLength(0);
    expect(result.vulnerabilities).toHaveLength(0);
    expect(result.cves).toHaveLength(0);
  });

  // -----------------------------------------------------------------------
  // 7. vulnerabilities, cves, serviceObservations は空配列
  // -----------------------------------------------------------------------
  it('vulnerabilities, cves, serviceObservations は空配列を返す', () => {
    const json = buildFfufJson({
      commandline: 'ffuf -u http://10.0.0.1:80/FUZZ -w wordlist.txt -o output.json -of json',
      url: 'http://10.0.0.1:80/FUZZ',
      method: 'GET',
      results: [
        buildResult({
          input: { FUZZ: 'admin' },
          position: 1,
          status: 200,
          length: 1234,
          words: 100,
          lines: 50,
          'content-type': 'text/html',
          url: 'http://10.0.0.1:80/admin',
          host: '10.0.0.1:80',
        }),
      ],
    });

    const result = parseFfufJson(json);

    // ffuf パーサーはこれらを生成しない
    expect(result.vulnerabilities).toEqual([]);
    expect(result.cves).toEqual([]);
    expect(result.serviceObservations).toEqual([]);
  });
});
