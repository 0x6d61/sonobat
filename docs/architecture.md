# sonobat — AttackDataGraph 設計書

## 1. 目的

sonobat は **AttackDataGraph** — 自律ペネトレーションテストのための正規化データストアである。

前身である pentecter（Go 製）の AttackDataTree（ホスト→ポート→サービス→エンドポイント→パラメータ）の概念を引き継ぎ、正規化 DB + GraphQL API として TypeScript で再実装する。

**コアコンセプト:**

- nmap / ffuf / nuclei の実行結果を **Artifact** として保存する
- Artifact を決定的にパースし、再利用可能な事実グラフ（Host → Service → Endpoint → Input → Observation）へ **正規化** する
- 正規化済みデータの欠損から次のアクション候補を **提案（propose）** する
- **MCP Server + GraphQL API** を提供し、LLM Agent が直接 sonobat を操作可能にする

**スコープ:**

| 含む | 含まない（v0.3 以降） |
|------|----------------------|
| nmap / ffuf / nuclei パーサー | 深い JS 解析・フォーム推定 |
| 事実の正規化・永続化 | 脆弱性自動判定 |
| 欠損駆動提案 | LLM Agent Runner（sonobat 外で実装） |
| **MCP Server** + GraphQL API + CLI | パラメータ/バリューサーチ（自作 or 外部ツール連携） |

---

## 2. アーキテクチャ概要

```
┌──────────────────────────────────────────┐
│  Consumer                                │
│  ┌──────────┐ ┌───────┐ ┌────────────┐  │
│  │ LLM Agent│ │ 人間  │ │ 外部ツール │  │
│  └────┬─────┘ └───┬───┘ └──────┬─────┘  │
│       │MCP        │CLI         │GraphQL  │
└───────┼───────────┼────────────┼─────────┘
┌───────▼───────────▼────────────▼─────────┐
│  sonobat（AttackDataGraph）               │
│  ┌──────────┐ ┌─────┐ ┌─────────────┐   │
│  │MCP Server│ │ CLI │ │ GraphQL API │   │
│  └────┬─────┘ └──┬──┘ └──────┬──────┘   │
│  ┌────▼──────────▼───────────▼────────┐  │
│  │   Engine                           │  │
│  │  ・Parser (nmap/ffuf/nuclei)       │  │
│  │  ・Normalizer                      │  │
│  │  ・Proposer (欠損駆動)              │  │
│  └──────────────┬─────────────────────┘  │
│  ┌──────────────▼─────────────────────┐  │
│  │   SQLite (better-sqlite3)          │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

### インターフェース層

sonobat は **3つのインターフェース** を同一の Engine 層に対して提供する:

| インターフェース | 用途 | プロトコル |
|----------------|------|----------|
| **MCP Server** | LLM Agent が直接操作 | MCP (stdio / SSE) |
| **CLI** | 人間が直接操作 | コマンドライン |
| **GraphQL API** | 外部ツール・UI が利用 | HTTP |

MCP Server が最優先。LLM が `ingest` → `propose` → 実行 → `ingest` のループを自律的に回せるようにする。

### データフロー

1. 外部ツール実行結果（XML/JSON/テキスト）を **Artifact** として登録（MCP / CLI / GraphQL いずれからでも可）
2. **Parser** が Artifact を読み、正規化した事実を DB に upsert
3. **Proposer** が欠損を分析し、次のアクション候補を返す
4. Consumer（LLM Agent/人間）がアクションを実行し、結果を再度登録

Runner（コマンド実行基盤）は本設計の外に置く。LLM Agent が自身のツール実行機能で Runner を担う想定。

---

## 3. データモデル

```
hosts ─────────────────────────────────────────────
  │
  ├── vhosts (バーチャルホスト名)
  │
  └── services (transport + port + app_proto)
        │
        ├── service_observations (key-value 観測)
        │
        ├── credentials (認証情報: username/secret)
        │     ※ SSH, FTP, HTTP 等あらゆるサービスに紐づく
        │     ※ HTTP の場合は endpoint_id で特定エンドポイントにも紐づけ可能
        │
        ├── http_endpoints (method + path)
        │     └── endpoint_inputs ──┐ (多対多)
        │                          │
        ├── inputs (location + name)┘
        │     └── observations (observed values)
        │
        └── vulnerabilities (発見された脆弱性)
              └── cves (紐づく CVE 情報、任意)

artifacts (全テーブルから evidence として参照)
scans (実行単位、任意)
```

### 設計原則

- **根拠必須** — すべての事実は根拠（`evidence_artifact_id`）に紐づく。由来不明の事実を禁止する
- **Endpoint に query string を含めない** — クエリパラメータは Input として管理する
- **base_uri = scheme://authority:port** — 80/443 も省略しない（例: `http://example.com:80`）
- **トップレベルエンティティは `hosts`** — vhost は別テーブルで管理
- **endpoint ↔ input は多対多** — `endpoint_inputs` 中間テーブルで関連付け

---

## 4. SQLite スキーマ

### 共通ルール

- ID: `TEXT PRIMARY KEY`（`crypto.randomUUID()`）
- タイムスタンプ: `TEXT`（ISO 8601 形式）
- JSON カラム: ツール固有属性・拡張用に限定
- `PRAGMA foreign_keys = ON` 必須

```sql
PRAGMA foreign_keys = ON;

-- ============================================================
-- 実行単位（任意）
-- ============================================================
CREATE TABLE IF NOT EXISTS scans (
  id            TEXT PRIMARY KEY,
  started_at    TEXT NOT NULL,
  finished_at   TEXT,
  notes         TEXT
);

-- ============================================================
-- 生出力（ファイル）参照
-- ============================================================
CREATE TABLE IF NOT EXISTS artifacts (
  id            TEXT PRIMARY KEY,
  scan_id       TEXT,
  tool          TEXT NOT NULL,              -- "nmap" | "ffuf" | "nuclei"
  kind          TEXT NOT NULL,              -- "tool_output" | "http_request" | "http_response"
  path          TEXT NOT NULL,              -- ローカルファイルパス or URI
  sha256        TEXT,
  captured_at   TEXT NOT NULL,
  attrs_json    TEXT,                       -- 任意メタ（コマンド、引数等）
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_tool ON artifacts(tool);

-- ============================================================
-- ホスト
-- ============================================================
CREATE TABLE IF NOT EXISTS hosts (
  id                TEXT PRIMARY KEY,
  authority_kind    TEXT NOT NULL,           -- "IP" | "DOMAIN"
  authority         TEXT NOT NULL UNIQUE,    -- IP アドレスまたはドメイン名
  resolved_ips_json TEXT NOT NULL DEFAULT '[]',
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

-- ============================================================
-- バーチャルホスト
-- ============================================================
CREATE TABLE IF NOT EXISTS vhosts (
  id                    TEXT PRIMARY KEY,
  host_id               TEXT NOT NULL,
  hostname              TEXT NOT NULL,
  source                TEXT,               -- "nmap" | "cert" | "header" | "manual"
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  UNIQUE (host_id, hostname),
  FOREIGN KEY (host_id)              REFERENCES hosts(id)     ON DELETE CASCADE,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_vhosts_host ON vhosts(host_id);

-- ============================================================
-- サービス
-- ============================================================
CREATE TABLE IF NOT EXISTS services (
  id                    TEXT PRIMARY KEY,
  host_id               TEXT NOT NULL,
  transport             TEXT NOT NULL,       -- "tcp" | "udp"
  port                  INTEGER NOT NULL,
  app_proto             TEXT NOT NULL,       -- "http" | "ssh" | "ftp" 等
  proto_confidence      TEXT NOT NULL,       -- "high" | "medium" | "low"
  banner                TEXT,
  product               TEXT,
  version               TEXT,
  state                 TEXT NOT NULL,       -- "open" | "closed" | "filtered"
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL,
  UNIQUE (host_id, transport, port),
  FOREIGN KEY (host_id)              REFERENCES hosts(id)     ON DELETE CASCADE,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);

-- ============================================================
-- サービス観測（key-value）
-- ============================================================
CREATE TABLE IF NOT EXISTS service_observations (
  id                    TEXT PRIMARY KEY,
  service_id            TEXT NOT NULL,
  key                   TEXT NOT NULL,
  value                 TEXT NOT NULL,
  confidence            TEXT NOT NULL,       -- "high" | "medium" | "low"
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  FOREIGN KEY (service_id)           REFERENCES services(id)  ON DELETE CASCADE,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_svc_obs_service ON service_observations(service_id);

-- ============================================================
-- HTTP エンドポイント
-- ============================================================
CREATE TABLE IF NOT EXISTS http_endpoints (
  id                    TEXT PRIMARY KEY,
  service_id            TEXT NOT NULL,
  vhost_id              TEXT,
  base_uri              TEXT NOT NULL,       -- "http://example.com:80"
  method                TEXT NOT NULL,       -- "GET" | "POST" | ...
  path                  TEXT NOT NULL,       -- "/admin"（クエリは含めない）
  status_code           INTEGER,
  content_length        INTEGER,
  words                 INTEGER,
  lines                 INTEGER,
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  UNIQUE (service_id, method, path),
  FOREIGN KEY (service_id)           REFERENCES services(id)  ON DELETE CASCADE,
  FOREIGN KEY (vhost_id)             REFERENCES vhosts(id)    ON DELETE SET NULL,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_endpoints_service ON http_endpoints(service_id);

-- ============================================================
-- 入力パラメータ
-- ============================================================
CREATE TABLE IF NOT EXISTS inputs (
  id            TEXT PRIMARY KEY,
  service_id    TEXT NOT NULL,
  location      TEXT NOT NULL,              -- "query" | "path" | "body" | "header" | "cookie"
  name          TEXT NOT NULL,
  type_hint     TEXT,                       -- "string" | "int" | "json" 等（任意）
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  UNIQUE (service_id, location, name),
  FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_inputs_service ON inputs(service_id);

-- ============================================================
-- エンドポイント ↔ 入力（多対多）
-- ============================================================
CREATE TABLE IF NOT EXISTS endpoint_inputs (
  id                    TEXT PRIMARY KEY,
  endpoint_id           TEXT NOT NULL,
  input_id              TEXT NOT NULL,
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  UNIQUE (endpoint_id, input_id),
  FOREIGN KEY (endpoint_id)          REFERENCES http_endpoints(id) ON DELETE CASCADE,
  FOREIGN KEY (input_id)             REFERENCES inputs(id)         ON DELETE CASCADE,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id)      ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_ep_inputs_endpoint ON endpoint_inputs(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_ep_inputs_input    ON endpoint_inputs(input_id);

-- ============================================================
-- 観測値
-- ============================================================
CREATE TABLE IF NOT EXISTS observations (
  id                    TEXT PRIMARY KEY,
  input_id              TEXT NOT NULL,
  raw_value             TEXT NOT NULL,
  norm_value            TEXT NOT NULL,
  body_path             TEXT,               -- JSON Pointer 等（例: "/user/name"）
  source                TEXT NOT NULL,       -- "ffuf_url" | "req_query" | "req_body" | "manual"
  confidence            TEXT NOT NULL,       -- "high" | "medium" | "low"
  evidence_artifact_id  TEXT NOT NULL,
  observed_at           TEXT NOT NULL,
  FOREIGN KEY (input_id)             REFERENCES inputs(id)    ON DELETE CASCADE,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_obs_input ON observations(input_id);

-- ============================================================
-- 認証情報
-- ============================================================
CREATE TABLE IF NOT EXISTS credentials (
  id                    TEXT PRIMARY KEY,
  service_id            TEXT NOT NULL,
  endpoint_id           TEXT,               -- HTTP の場合のみ（任意）
  username              TEXT NOT NULL,
  secret                TEXT NOT NULL,
  secret_type           TEXT NOT NULL,       -- "password" | "token" | "api_key" | "ssh_key"
  source                TEXT NOT NULL,       -- "brute_force" | "default" | "leaked" | "manual"
  confidence            TEXT NOT NULL,       -- "high" | "medium" | "low"
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  FOREIGN KEY (service_id)           REFERENCES services(id)       ON DELETE CASCADE,
  FOREIGN KEY (endpoint_id)          REFERENCES http_endpoints(id) ON DELETE SET NULL,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id)      ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_creds_service  ON credentials(service_id);
CREATE INDEX IF NOT EXISTS idx_creds_endpoint ON credentials(endpoint_id);

-- ============================================================
-- 脆弱性
-- ============================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id                    TEXT PRIMARY KEY,
  service_id            TEXT NOT NULL,
  endpoint_id           TEXT,               -- HTTP の場合のみ（任意）
  vuln_type             TEXT NOT NULL,       -- "sqli" | "xss" | "rce" | "lfi" | "ssrf" | ...
  title                 TEXT NOT NULL,
  description           TEXT,
  severity              TEXT NOT NULL,       -- "critical" | "high" | "medium" | "low" | "info"
  confidence            TEXT NOT NULL,       -- "high" | "medium" | "low"
  evidence_artifact_id  TEXT NOT NULL,
  created_at            TEXT NOT NULL,
  FOREIGN KEY (service_id)           REFERENCES services(id)       ON DELETE CASCADE,
  FOREIGN KEY (endpoint_id)          REFERENCES http_endpoints(id) ON DELETE SET NULL,
  FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts(id)      ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_vulns_service  ON vulnerabilities(service_id);
CREATE INDEX IF NOT EXISTS idx_vulns_endpoint ON vulnerabilities(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);

-- ============================================================
-- CVE 情報
-- ============================================================
CREATE TABLE IF NOT EXISTS cves (
  id                TEXT PRIMARY KEY,
  vulnerability_id  TEXT NOT NULL,
  cve_id            TEXT NOT NULL,          -- "CVE-YYYY-NNNNN"
  description       TEXT,
  cvss_score        REAL,
  cvss_vector       TEXT,
  reference_url     TEXT,
  created_at        TEXT NOT NULL,
  FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cves_vuln ON cves(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_cves_cveid ON cves(cve_id);
```

---

## 5. GraphQL スキーマ

SQL テーブルと 1:1 対応する Type を定義する。

```graphql
scalar JSON
scalar DateTime

# ============================================================
# Query
# ============================================================
type Query {
  # ホスト
  hosts: [Host!]!
  host(id: ID!): Host

  # バーチャルホスト
  vhosts(hostId: ID!): [Vhost!]!

  # サービス
  services(hostId: ID!): [Service!]!
  service(id: ID!): Service

  # サービス観測
  serviceObservations(serviceId: ID!): [ServiceObservation!]!

  # HTTP エンドポイント
  httpEndpoints(serviceId: ID!): [HttpEndpoint!]!

  # 入力パラメータ
  inputs(serviceId: ID!, location: String): [Input!]!

  # 観測値
  observations(inputId: ID!): [Observation!]!

  # 認証情報
  credentials(serviceId: ID): [Credential!]!

  # 脆弱性
  vulnerabilities(serviceId: ID, severity: String): [Vulnerability!]!

  # CVE 情報
  cves(vulnerabilityId: ID): [Cve!]!

  # 欠損駆動提案
  propose(hostId: ID): [Action!]!
}

# ============================================================
# Mutation
# ============================================================
type Mutation {
  # Artifact 登録
  registerArtifact(tool: String!, kind: String!, path: String!, attrs: JSON): ID!

  # 正規化実行
  normalize(artifactId: ID!): Boolean!

  # ホスト追加
  createHost(authority: String!, authorityKind: String!): Host!

  # vhost 追加
  addVhost(hostId: ID!, hostname: String!, source: String): Vhost!

  # 認証情報追加
  addCredential(
    serviceId: ID!
    username: String!
    secret: String!
    secretType: String!
    source: String!
    endpointId: ID
    confidence: String
  ): Credential!

  # 脆弱性登録
  addVulnerability(
    serviceId: ID!
    vulnType: String!
    title: String!
    severity: String!
    confidence: String!
    endpointId: ID
    description: String
  ): Vulnerability!

  # CVE 紐づけ
  linkCve(
    vulnerabilityId: ID!
    cveId: String!
    description: String
    cvssScore: Float
    cvssVector: String
    referenceUrl: String
  ): Cve!
}

# ============================================================
# Types
# ============================================================
type Host {
  id: ID!
  authorityKind: String!
  authority: String!
  resolvedIps: JSON!
  createdAt: DateTime!
  updatedAt: DateTime!
  vhosts: [Vhost!]!
  services: [Service!]!
}

type Vhost {
  id: ID!
  hostId: ID!
  hostname: String!
  source: String
  evidenceArtifactId: ID!
  createdAt: DateTime!
}

type Service {
  id: ID!
  hostId: ID!
  transport: String!
  port: Int!
  appProto: String!
  protoConfidence: String!
  banner: String
  product: String
  version: String
  state: String!
  evidenceArtifactId: ID!
  createdAt: DateTime!
  updatedAt: DateTime!
  observations: [ServiceObservation!]!
  httpEndpoints: [HttpEndpoint!]!
  credentials: [Credential!]!
  vulnerabilities: [Vulnerability!]!
}

type ServiceObservation {
  id: ID!
  serviceId: ID!
  key: String!
  value: String!
  confidence: String!
  evidenceArtifactId: ID!
  createdAt: DateTime!
}

type HttpEndpoint {
  id: ID!
  serviceId: ID!
  vhostId: ID
  baseUri: String!
  method: String!
  path: String!
  statusCode: Int
  contentLength: Int
  words: Int
  lines: Int
  evidenceArtifactId: ID!
  createdAt: DateTime!
  inputs: [Input!]!
}

type Input {
  id: ID!
  serviceId: ID!
  location: String!
  name: String!
  typeHint: String
  createdAt: DateTime!
  updatedAt: DateTime!
  observations: [Observation!]!
}

type Observation {
  id: ID!
  inputId: ID!
  rawValue: String!
  normValue: String!
  bodyPath: String
  source: String!
  confidence: String!
  evidenceArtifactId: ID!
  observedAt: DateTime!
}

type Credential {
  id: ID!
  serviceId: ID!
  endpointId: ID
  username: String!
  secret: String!
  secretType: String!
  source: String!
  confidence: String!
  evidenceArtifactId: ID!
  createdAt: DateTime!
}

type Vulnerability {
  id: ID!
  serviceId: ID!
  endpointId: ID
  vulnType: String!
  title: String!
  description: String
  severity: String!
  confidence: String!
  evidenceArtifactId: ID!
  createdAt: DateTime!
  cves: [Cve!]!
}

type Cve {
  id: ID!
  vulnerabilityId: ID!
  cveId: String!
  description: String
  cvssScore: Float
  cvssVector: String
  referenceUrl: String
  createdAt: DateTime!
}

type Action {
  kind: String!
  description: String!
  command: String
  params: JSON
}
```

---

## 6. 欠損駆動提案（propose）

pentecter の ReconRunner が固定フェーズで行っていたことを、データの欠損から自動提案する。

| 欠損パターン | 提案アクション |
|-------------|--------------|
| host にサービス情報なし | `nmap -p- -sV {host}` |
| HTTP サービスにエンドポイントなし | `ffuf -u {base_uri}/FUZZ` |
| エンドポイントに input なし | パラメータディスカバリ |
| input に observation なし | 値収集・テスト |
| HTTP サービスに vhost なし | vhost ディスカバリ |
| HTTP サービスに脆弱性スキャン未実施 | `nuclei -u {base_uri}` |
| サービスに認証情報なし | デフォルトクレデンシャル確認 |
| 脆弱性に CVE 紐づけなし | CVE データベース検索 |

Proposer は `propose(hostId?)` クエリで呼び出す。hostId を省略すると全ホストを対象にする。

---

## 7. MCP Server ツール設計

LLM Agent が sonobat を操作するための MCP ツール一覧。各ツールは Engine 層の関数を直接呼び出す。

### Ingest（取り込み）

| ツール名 | 引数 | 説明 |
|---------|------|------|
| `ingest_file` | `path`, `tool` (nmap\|ffuf\|nuclei) | ファイルを Artifact として登録し、正規化を実行。戻り値: 生成されたエンティティの要約 |

### Query（照会）

| ツール名 | 引数 | 説明 |
|---------|------|------|
| `list_hosts` | — | 全ホスト一覧 |
| `get_host` | `hostId` | ホスト詳細（services, vhosts 含む） |
| `list_services` | `hostId` | 指定ホストのサービス一覧 |
| `list_endpoints` | `serviceId` | 指定サービスの HTTP エンドポイント一覧 |
| `list_inputs` | `serviceId`, `location?` | 指定サービスの入力パラメータ一覧 |
| `list_observations` | `inputId` | 指定入力の観測値一覧 |
| `list_credentials` | `serviceId?` | 認証情報一覧 |
| `list_vulnerabilities` | `serviceId?`, `severity?` | 脆弱性一覧 |

### Propose（提案）

| ツール名 | 引数 | 説明 |
|---------|------|------|
| `propose` | `hostId?` | 欠損駆動で次のアクション候補を返す |

### Mutation（変更）

| ツール名 | 引数 | 説明 |
|---------|------|------|
| `add_host` | `authority`, `authorityKind` | ホスト手動追加 |
| `add_credential` | `serviceId`, `username`, `secret`, `secretType`, `source` | 認証情報追加 |
| `add_vulnerability` | `serviceId`, `vulnType`, `title`, `severity`, ... | 脆弱性手動登録 |
| `link_cve` | `vulnerabilityId`, `cveId`, ... | CVE 紐づけ |

### MCP Resource（読み取り専用データ）

| リソース URI | 説明 |
|-------------|------|
| `sonobat://hosts` | ホスト一覧（JSON） |
| `sonobat://hosts/{id}` | ホスト詳細 + 配下のサービスツリー |
| `sonobat://summary` | 全体統計（ホスト数、サービス数、脆弱性数等） |

### 設計原則

- MCP ツールと GraphQL Mutation/Query は **同じ Engine 関数** を呼ぶ（実装の重複を避ける）
- MCP ツールの戻り値は LLM が解釈しやすい **テキスト/JSON** 形式
- stdio トランスポートを基本とし、Claude Code / Claude Desktop からそのまま使える

---

## 8. CLI コマンド設計

```
sonobat init                                    DB 初期化
sonobat serve [--mcp] [--graphql]               サーバー起動（デフォルト: MCP stdio）
sonobat ingest <file> --tool nmap|ffuf|nuclei     Artifact 登録 + 正規化
sonobat propose [--host-id <id>]                 次アクション提案
sonobat query hosts|services|endpoints|...       データ照会
```

CLI は人間が直接操作するための最小限のインターフェース。LLM からの操作は MCP Server 経由。

---

## 9. 技術スタック

| 項目 | 選定 | 備考 |
|------|------|------|
| 言語 | TypeScript 5.x (strict mode) | `tsconfig.json` の `strict: true` 必須 |
| ランタイム | Node.js >= 20 LTS | ES2022 ターゲット |
| パッケージマネージャー | npm | `package-lock.json` をコミットする |
| テスト | Vitest | Jest 互換 API、TypeScript ネイティブ |
| SQLite | better-sqlite3 | 同期 API |
| MCP | `@modelcontextprotocol/sdk` | MCP TypeScript SDK（stdio トランスポート） |
| XML パーサー | fast-xml-parser | nmap XML パース用。Pure JS |
| ビルド | tsup | esbuild ベース |
| リンター | ESLint + @typescript-eslint | flat config |
| フォーマッター | Prettier | `.prettierrc` で統一 |
| GraphQL | 未選定 | graphql-yoga / Apollo 等を検討 |

---

## 10. 将来拡張（v0.3+）

- **http_transactions テーブル** — Burp/ZAP のリクエスト・レスポンスログを保存
- **パラメータ/バリューサーチツール** — 自作 or 外部ツール（Arjun, ParamSpider, katana 等）連携
- **LLM Agent Runner** — pentecter 後継。MCP 経由で sonobat を操作する外部エージェント
- **深い JS 解析・フォーム推定** — SPA のパラメータ自動抽出
- **脆弱性自動判定** — Observation からの自動分類
- **レポート生成** — JSON/HTML 形式でのエクスポート
- **MCP SSE トランスポート** — リモート環境からの MCP 接続
