# Sonobat 開発ガイド

## プロジェクト概要

Sonobat は、認可されたペネトレーションテストの調査状態を保持、検索する MCP Server である。
TypeScript で実装され、現行の永続化ストアは SQLite、MCP transport は stdio である。
Sonobat は調査計画、外部コマンド実行、作業割り当てを担当しない。

詳細な設計は [Sonobat Core Model](https://github.com/0x6d61/sonobat/wiki/Sonobat-Core-Model) を参照すること。

## 開発環境

必須:

- Node.js 20 以上
- npm（`package-lock.json` を使用し、CI とクリーン環境では `npm ci`）
- better-sqlite3 の native addon を利用できるビルド/実行環境
- Linux/WSL で Node が `libatomic.so.1` を要求する場合は OS の libatomic runtime

主なコマンド:

```bash
npm ci
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
```

`npm run test:coverage` には Vitest の coverage provider が必要である。依存を追加・更新した場合は
lockfile を必ず更新すること。

## プロジェクト構造

```text
src/
├── index.ts             # 現行 stdio MCP entrypoint
├── db/
│   ├── migrate.ts
│   ├── migrations/      # versioned schema migrations
│   └── repository/
├── engine/              # KB index
├── mcp/                 # core server and tools
└── types/
tests/                   # src の構造に対応する Vitest tests
```

存在しない `src/cli/` を前提にしないこと。

## 開発プロセス

- TDD を基本とし、Red → Green → Refactor の順で進める。
- 変更範囲に応じて format、lint、typecheck、test、build を実行する。
- 公開MCP toolとschemaの互換性は、ユーザーが必要とする場合に限り維持する。
- MCP tool/resource、schema、repository、parser、transport、entrypoint、環境変数を変更するときは、
  GitHub Wiki の Sonobat Core Model を同じ変更単位で更新する。
- スキーマ変更は `src/db/migrations/` に新しい version として追加し、既存 migration を
  書き換えない。
- 新規依存を追加する前に、必要性、代替案、runtime/dev dependency の区分を確認する。
- GitHub Flow を使う場合は `feature/<issue番号>-<説明>` とし、PR に `Closes #<issue番号>` を
  含める。ブランチ作成、Issue/PR 操作、push はユーザーの依頼または承認の範囲で行う。

## TypeScript 規約

- `strict: true` を維持する。
- 外部入力は `unknown` として受け、Zod または型ガードで検証する。`any` は原則禁止。
- public な関数・メソッドには戻り値の型を明示する。
- ESM と `.js` 拡張子付き相対 import を使う。
- ファイル名は kebab-case、値/関数は camelCase、型は PascalCase、定数は UPPER_SNAKE_CASE。
- SQL の値は prepared statement で渡し、複数 write は transaction でまとめる。
- ID は `crypto.randomUUID()`、時刻は ISO 8601 文字列を基本とする。
- DB 固有 SQL を MCP handler や engine に追加しない。PostgreSQL 対応に向け、DB 差異は
  repository/adapter/migration 境界へ閉じ込める。

## テスト規約

- `tests/` に `*.test.ts` として配置する。
- 各テストを独立させ、SQLite repository/migration test は原則 `:memory:` を使う。
- transport、DB adapter、repository の追加時は成功系だけでなく、競合、不正入力、切断もテストする。
- SQLite と PostgreSQL の共通 contract test を用意し、adapter 間の意味論を揃える。

## セキュリティ境界

- Assessment の scope を Entity、Relation、Activity、Artifact の保存と検索で検証する。
- Sonobat は shell 文字列や外部コマンドを実行しない。
- HTTP transport では認証、認可、TLS/信頼境界、session isolation、request size limit を明示する。
- Credentialの `value`はqueryで返すが、ログやMCP errorには出さない。
- パス入力は resolve 後に許可 root 配下であることを検証する。
- `.env` や DB、artifact、秘密情報を Git に含めない。

## 環境変数（現行）

- `SONOBAT_DB_PATH`: SQLite DB path。既定値は `sonobat.db`
- `SONOBAT_ARTIFACT_DIR`: Artifact の保存を許可する root。既定値は `~/.sonobat/artifacts/`

将来の HTTP/DB 選択用設定名は、実装と同時に定義し、README とこの文書を更新すること。
