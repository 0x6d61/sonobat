# sonobat — AttackDataGraph 設計書

## 1. 目的

sonobat は **AttackDataGraph** — 自律ペネトレーションテストのための正規化データストアである。

前身である pentecter（Go 製）の AttackDataTree の概念を引き継ぎ、**グラフネイティブ DB + MCP Server** として TypeScript で再実装した。

**コアコンセプト:**

- nmap / ffuf / nuclei の実行結果を **Artifact** として保存する
- Artifact を決定的にパースし、再利用可能な攻撃グラフ（`nodes` + `edges`）へ **正規化** する
- 正規化済みデータの欠損から次のアクション候補を **提案（propose）** する
- **HackTricks ナレッジベース** を FTS5 全文検索で提供する（自動 clone + 増分インデックス）
- **MCP Server** を提供し、LLM Agent が直接 sonobat を操作可能にする

**スコープ:**

| 含む | 含まない |
|------|---------|
| nmap / ffuf / nuclei パーサー | 深い JS 解析・フォーム推定 |
| グラフネイティブ正規化・永続化 | 脆弱性自動判定 |
| 欠損駆動提案 | LLM Agent Runner（sonobat 外で実装） |
| HackTricks KB（自動 clone + 増分インデックス） | パラメータ/バリューサーチ |
| MCP Server（stdio トランスポート） | |

---

## 2. アーキテクチャ概要

```
┌──────────────────────────────────────────┐
│  Consumer                                │
│  ┌──────────────────────────────────┐    │
│  │ LLM Agent（Claude Code 等）      │    │
│  └────────────┬─────────────────────┘    │
│               │MCP (stdio)               │
└───────────────┼──────────────────────────┘
┌───────────────▼──────────────────────────┐
│  sonobat（AttackDataGraph）               │
│  ┌──────────────────────────────────┐    │
│  │  MCP Server                      │    │
│  │  ・6 Tools + 4 Resources         │    │
│  └──────────────┬───────────────────┘    │
│  ┌──────────────▼───────────────────┐    │
│  │   Engine                         │    │
│  │  ・Parser (nmap/ffuf/nuclei)     │    │
│  │  ・Normalizer                    │    │
│  │  ・Proposer (欠損駆動)            │    │
│  │  ・Indexer (増分 KB インデックス)   │    │
│  │  ・Git Ops (auto-clone/pull)     │    │
│  └──────────────┬───────────────────┘    │
│  ┌──────────────▼───────────────────┐    │
│  │   SQLite (better-sqlite3)        │    │
│  │  ・nodes + edges (グラフ)         │    │
│  │  ・technique_docs + FTS5 (KB)     │    │
│  │  ・artifacts (証跡)               │    │
│  └──────────────────────────────────┘    │
└──────────────────────────────────────────┘
```

### インターフェース層

**MCP Server** を唯一のインターフェースとして提供する。LLM が `ingest` → `propose` → 実行 → `ingest` のループを自律的に回せる設計。

### データフロー

1. 外部ツール実行結果（XML/JSON/JSONL）を **Artifact** として MCP 経由で登録
2. **Parser** が Artifact を読み、正規化した事実を `nodes` + `edges` に upsert
3. **Proposer** が欠損を分析し、次のアクション候補を返す
4. LLM Agent がアクションを実行し、結果を再度登録

Runner（コマンド実行基盤）は本設計の外に置く。LLM Agent が自身のツール実行機能で Runner を担う想定。

---

## 3. データモデル（グラフネイティブ）

v0.4.0 で 12 エンティティテーブルから `nodes` + `edges` のグラフネイティブスキーマに移行した。

### ノード種別（10 種）

```
nodes (kind + props_json)
 ├── host              — IP or ドメインターゲット
 ├── vhost             — バーチャルホスト
 ├── service           — Transport + port + protocol
 ├── endpoint          — HTTP method + path
 ├── input             — パラメータ (query, body, header, etc.)
 ├── observation       — 観測値
 ├── credential        — 認証情報
 ├── vulnerability     — 検出された脆弱性
 ├── cve               — CVE レコード
 └── svc_observation   — サービスレベル key-value 観測
```

### エッジ種別（13 種）

```
edges (kind + source_id + target_id)
 HOST_SERVICE, HOST_VHOST, SERVICE_ENDPOINT, SERVICE_INPUT,
 SERVICE_CREDENTIAL, SERVICE_VULNERABILITY, SERVICE_OBSERVATION,
 ENDPOINT_INPUT, ENDPOINT_VULNERABILITY, ENDPOINT_CREDENTIAL,
 INPUT_OBSERVATION, VULNERABILITY_CVE, VHOST_ENDPOINT
```

### Natural Key 戦略

確定的ノードにはユニークな `natural_key` を生成し、upsert で冪等性を保証する。

| ノード種別 | Natural Key | 確定的？ |
|-----------|-------------|---------|
| host | `host:{authority}` | Yes |
| vhost | `vhost:{parentId}:{hostname}` | Yes |
| service | `svc:{parentId}:{transport}:{port}` | Yes |
| endpoint | `ep:{parentId}:{method}:{path}` | Yes |
| input | `in:{parentId}:{location}:{name}` | Yes |
| cve | `cve:{parentId}:{cveId}` | Yes |
| observation | `obs:{UUID}` | No |
| credential | `cred:{UUID}` | No |
| vulnerability | `vuln:{UUID}` | No |
| svc_observation | `svcobs:{UUID}` | No |

### 設計原則

- **根拠必須** — すべてのノード/エッジは `evidence_artifact_id` で証跡に紐づく
- **Props-as-JSON** — ノード/エッジのプロパティは `props_json` カラムに Zod バリデーション付きで格納
- **エッジのユニーク制約** — `(kind, source_id, target_id)` で重複エッジを防止
- **トランザクション** — 複数ノード/エッジの変更は `db.transaction()` でアトミックに実行

---

## 4. SQLite スキーマ

### 共通ルール

- ID: `TEXT PRIMARY KEY`（`crypto.randomUUID()`）
- タイムスタンプ: `TEXT`（ISO 8601 形式）
- `PRAGMA foreign_keys = ON` 必須
- マイグレーション: `PRAGMA user_version` でバージョン管理（v0 → v5）

### コアテーブル

```sql
-- ============================================================
-- グラフ: ノード
-- ============================================================
CREATE TABLE nodes (
  id                    TEXT PRIMARY KEY,
  kind                  TEXT NOT NULL,
  natural_key           TEXT NOT NULL UNIQUE,
  props_json            TEXT NOT NULL DEFAULT '{}',
  evidence_artifact_id  TEXT REFERENCES artifacts(id),
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL
);

CREATE INDEX idx_nodes_kind ON nodes(kind);
CREATE INDEX idx_nodes_evidence ON nodes(evidence_artifact_id);

-- ============================================================
-- グラフ: エッジ
-- ============================================================
CREATE TABLE edges (
  id                    TEXT PRIMARY KEY,
  kind                  TEXT NOT NULL,
  source_id             TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  target_id             TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  props_json            TEXT NOT NULL DEFAULT '{}',
  evidence_artifact_id  TEXT REFERENCES artifacts(id),
  created_at            TEXT NOT NULL,
  UNIQUE(kind, source_id, target_id)
);

CREATE INDEX idx_edges_source ON edges(source_id);
CREATE INDEX idx_edges_target ON edges(target_id);
CREATE INDEX idx_edges_kind ON edges(kind);

-- ============================================================
-- 証跡
-- ============================================================
CREATE TABLE artifacts (
  id            TEXT PRIMARY KEY,
  scan_id       TEXT,
  tool          TEXT NOT NULL,
  kind          TEXT NOT NULL,
  path          TEXT NOT NULL,
  sha256        TEXT,
  captured_at   TEXT NOT NULL,
  attrs_json    TEXT,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

-- ============================================================
-- ナレッジベース (HackTricks)
-- ============================================================
CREATE TABLE technique_docs (
  id            TEXT PRIMARY KEY,
  source        TEXT NOT NULL,
  file_path     TEXT NOT NULL,
  title         TEXT NOT NULL,
  category      TEXT NOT NULL,
  content       TEXT NOT NULL,
  chunk_index   INTEGER NOT NULL,
  indexed_at    TEXT NOT NULL,
  file_mtime    TEXT                    -- v5: 増分インデックス用
);

CREATE INDEX idx_technique_docs_source_filepath
  ON technique_docs(source, file_path);  -- v5: mtime 検索用

CREATE VIRTUAL TABLE technique_docs_fts USING fts5(
  title, category, content,
  content=technique_docs,
  content_rowid=rowid,
  tokenize='porter unicode61'
);
-- INSERT/UPDATE/DELETE トリガーで FTS5 自動同期
```

### マイグレーション履歴

| Version | 内容 |
|---------|------|
| v0 | ベーススキーマ（12 エンティティテーブル） |
| v1 | `datalog_rules` テーブル追加 |
| v2 | `vulnerabilities.status` カラム追加 |
| v3 | `technique_docs` + FTS5 テーブル追加 |
| v4 | グラフネイティブ化（`nodes` + `edges`、旧 12 テーブルを DROP） |
| v5 | `technique_docs.file_mtime` + 複合インデックス追加 |

---

## 5. 欠損駆動提案（propose）

データの欠損パターンから次のアクションを自動提案する。

| 欠損パターン | 提案アクション | コマンド例 |
|-------------|---------------|-----------|
| host にサービス情報なし | `nmap_scan` | `nmap -p- -sV {host}` |
| HTTP サービスにエンドポイントなし | `ffuf_discovery` | `ffuf -u {base_uri}/FUZZ -w ...` |
| エンドポイントに input なし | `parameter_discovery` | — |
| input に observation なし | `value_collection` | — |
| input に observation あり + 脆弱性なし | `value_fuzz` | — |
| HTTP サービスに vhost なし | `vhost_discovery` | — |
| HTTP サービスに脆弱性スキャン未実施 | `nuclei_scan` | `nuclei -u {base_uri} -jsonl` |

Proposer は `propose(hostId?)` で呼び出す。hostId を省略すると全ホストを対象にする。

---

## 6. MCP Server ツール設計

### ツール一覧（6 ツール）

| ツール | アクション / 説明 |
|--------|------------------|
| **`query`** | `list_nodes` — ノード一覧（kind + JSON フィルタ） |
| | `get_node` — ノード詳細（隣接エッジ + 隣接ノード） |
| | `traverse` — BFS グラフ走査（depth + edgeKinds） |
| | `summary` — ノード/エッジ/アーティファクト統計 |
| | `attack_paths` — プリセットパターン分析 |
| **`mutate`** | `add_node` — ノード作成/upsert（Zod バリデーション） |
| | `add_edge` — エッジ作成 |
| | `update_node` — ノード props 部分更新 |
| | `delete_node` — ノード削除（エッジ CASCADE） |
| **`ingest_file`** | ツール出力ファイル（nmap/ffuf/nuclei）の取り込み + 正規化 |
| **`propose`** | 欠損駆動で次のアクション候補を返す |
| **`search_kb`** | HackTricks ナレッジベースを FTS5 全文検索 |
| **`index_kb`** | HackTricks を自動 clone/pull + 増分インデックス |

### Attack Path プリセット

| パターン | 説明 |
|---------|------|
| `attack_surface` | Host → endpoint + input 完全パス |
| `critical_vulns` | Host → service → vulnerability（critical/high） |
| `credential_exposure` | Service → credential マッピング |
| `unscanned_services` | エンドポイント未発見のサービス |
| `vuln_by_host` | ホスト別脆弱性カウント |
| `reachable_services` | ホストから到達可能なサービス |

### MCP リソース（4 リソース）

| URI | 説明 |
|-----|------|
| `sonobat://nodes` | ノード一覧（kind フィルタ可） |
| `sonobat://nodes/{id}` | ノード詳細 + エッジ + 隣接ノード |
| `sonobat://summary` | 全体統計 |
| `sonobat://techniques/categories` | ナレッジベースのカテゴリ一覧 |

### 設計原則

- MCP ツールの戻り値は LLM が解釈しやすい **テキスト/JSON** 形式
- stdio トランスポートを基本とし、Claude Code / Claude Desktop からそのまま使える
- `mutate` で `evidenceArtifactId` 省略時はシングルトン "manual" Artifact を自動生成

---

## 7. ナレッジベース（HackTricks）

### 概要

HackTricks のマークダウンファイルを H2 境界でチャンク分割し、FTS5 全文検索インデックスとして提供する。

### 自動 clone + 増分インデックス

`index_kb` を path なしで呼ぶと以下のフローが実行される:

```
path指定あり → そのまま indexHacktricks(db, path)
path指定なし →
  defaultDir = ~/.sonobat/data/hacktricks/
  ensureDataDir()
  if (defaultDir が存在しない):
    git clone --depth 1 hacktricks → defaultDir
  else if (update !== false):
    git pull --ff-only
  indexHacktricks(db, defaultDir)  // 増分インデックス
```

### 増分インデックスアルゴリズム

1. DB から既存 `file_path → file_mtime` マップ取得
2. ディスク上の `.md` ファイル列挙 + 各ファイルの `stat.mtime` 取得
3. 分類: **新規** / **更新**（mtime 不一致）/ **削除**（DB のみ）/ **変更なし**（スキップ）
4. 削除・更新ファイルの docs を DELETE
5. 新規・更新ファイルをパース → INSERT
6. `IndexResult` を返す（totalChunks, newFiles, updatedFiles, deletedFiles, skippedFiles）

### データディレクトリ

| 項目 | 値 |
|------|-----|
| デフォルト | `~/.sonobat/data/` |
| HackTricks | `~/.sonobat/data/hacktricks/` |
| 環境変数オーバーライド | `SONOBAT_DATA_DIR` |

### Git 操作

- `execFile`（promisified）使用。シェル経由禁止
- `clone`: `git clone --depth 1`
- `pull`: `git pull --ff-only`
- タイムアウト: 5 分
- エラー分類: `git_not_found`, `clone_failed`, `pull_failed`, `permission_denied`, `network_error`, `directory_not_found`

---

## 8. ノード Props スキーマ

すべてのノード props は Zod スキーマで書き込み時にバリデーションされる。

| ノード種別 | 必須フィールド | オプション |
|-----------|---------------|----------|
| **host** | authorityKind, authority, resolvedIpsJson | — |
| **vhost** | hostname | source |
| **service** | transport, port, appProto, protoConfidence, state | banner, product, version |
| **endpoint** | baseUri, method, path | statusCode, contentLength, words, lines |
| **input** | location, name | typeHint |
| **observation** | rawValue, normValue, source, confidence, observedAt | bodyPath |
| **credential** | username, secret, secretType, source, confidence | — |
| **vulnerability** | vulnType, title, severity, confidence, status | description |
| **cve** | cveId | description, cvssScore, cvssVector, referenceUrl |
| **svc_observation** | key, value, confidence | — |

---

## 9. 技術スタック

| 項目 | 選定 | 備考 |
|------|------|------|
| 言語 | TypeScript 5.x (strict mode) | `strict: true` 必須 |
| ランタイム | Node.js >= 20 LTS | ES2022 ターゲット |
| パッケージマネージャー | npm | `package-lock.json` をコミット |
| テスト | Vitest | Jest 互換 API |
| SQLite | better-sqlite3 | 同期 API |
| MCP | `@modelcontextprotocol/sdk` | stdio トランスポート |
| XML パーサー | fast-xml-parser | nmap XML パース用 |
| バリデーション | Zod | ノード props バリデーション |
| ビルド | tsup | esbuild ベース |
| リンター | ESLint + @typescript-eslint | flat config |
| フォーマッター | Prettier | `.prettierrc` で統一 |

---

## 10. プロジェクト構造

```
sonobat/
├── src/
│   ├── index.ts              # エントリポイント
│   ├── db/
│   │   ├── schema.ts         # CREATE TABLE 定義
│   │   ├── migrate.ts        # マイグレーション実行
│   │   ├── migrations/       # v0〜v5 マイグレーション
│   │   └── repository/       # テーブルごとの CRUD 操作
│   │       ├── node-repository.ts
│   │       ├── edge-repository.ts
│   │       ├── graph-query-repository.ts
│   │       └── technique-doc-repository.ts
│   ├── parser/               # nmap, ffuf, nuclei パーサー
│   ├── engine/
│   │   ├── normalizer.ts     # パース結果 → グラフ正規化
│   │   ├── proposer.ts       # 欠損駆動提案
│   │   ├── indexer.ts        # HackTricks 増分インデックス
│   │   ├── data-dir.ts       # データディレクトリ管理
│   │   ├── git-ops.ts        # Git clone/pull 操作
│   │   └── ingest.ts         # ファイル取り込みオーケストレーション
│   ├── mcp/
│   │   ├── server.ts         # MCP Server 初期化
│   │   ├── tools/            # query, mutate, ingest, propose, kb
│   │   └── resources.ts      # MCP リソース定義
│   └── types/
│       ├── graph.ts          # ノード/エッジ型 + Zod スキーマ
│       ├── parser.ts         # パーサー中間型
│       └── engine.ts         # エンジン入出力型
├── tests/                    # src/ と同構造のミラー
├── docs/
│   └── architecture.md       # 本ドキュメント
├── tsconfig.json
├── vitest.config.ts
└── package.json
```

---

## 11. 環境変数

| 変数 | デフォルト | 説明 |
|------|-----------|------|
| `SONOBAT_DB_PATH` | `sonobat.db` | SQLite データベースファイルパス |
| `SONOBAT_DATA_DIR` | `~/.sonobat/data/` | 自動 clone データディレクトリ |

---

## 12. 将来拡張

- **http_transactions テーブル** — Burp/ZAP のリクエスト・レスポンスログを保存
- **パラメータ/バリューサーチ** — Arjun, ParamSpider, katana 等との連携
- **LLM Agent Runner** — pentecter 後継。MCP 経由で sonobat を操作する外部エージェント
- **深い JS 解析・フォーム推定** — SPA のパラメータ自動抽出
- **脆弱性自動判定** — Observation からの自動分類
- **レポート生成** — JSON/HTML 形式でのエクスポート
- **MCP SSE トランスポート** — リモート環境からの MCP 接続
- **Engagement / Run / Action Queue** — 継続的テスト基盤（`docs/v5-db-design.md` 参照）
