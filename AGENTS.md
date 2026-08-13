# Sonobat 開発ガイド

## プロジェクト概要

Sonobat は、自律ペネトレーションテスト向けの AttackDataGraph と MCP Server である。
TypeScript で実装され、現行の永続化ストアは SQLite、MCP transport は stdio である。

詳細な設計は [Architecture](https://github.com/0x6d61/sonobat/wiki/Architecture)、現在の実装と
目標アーキテクチャは
[Implementation Status](https://github.com/0x6d61/sonobat/wiki/Implementation-Status)、
継続的ペネトレーションテスト用の運用スキーマは
[v5 DB Design](https://github.com/0x6d61/sonobat/wiki/v5-DB-Design) を参照すること。

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
│   ├── migrations/      # v0〜v6
│   └── repository/
├── engine/              # propose、KB index
├── mcp/                 # server、tools、resources
└── types/
tests/                   # src の構造に対応する Vitest tests
```

存在しない `src/cli/` を前提にしないこと。新しい entrypoint や transport を追加するときは、
stdio の既存利用者を壊さない構成にする。

## 開発プロセス

- TDD を基本とし、Red → Green → Refactor の順で進める。
- 変更範囲に応じて format、lint、typecheck、test、build を実行する。
- 既存の公開 MCP tool/resource と SQLite migration の後方互換性を維持する。
- MCP tool/resource、schema、repository、parser、transport、entrypoint、環境変数を変更するときは、
  GitHub Wiki の Architecture と Implementation Status を同じ変更単位で更新する。
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
- transport、DB adapter、queue lease の追加時は成功系だけでなく、競合、期限切れ、再試行、
  不正入力、切断もテストする。
- SQLite と PostgreSQL の共通 contract test を用意し、adapter 間の意味論を揃える。

## セキュリティ境界

- 対象 scope と policy をすべての action 実行前に検証する。
- Worker は shell 文字列を直接実行せず、許可された executable と引数配列を使う。
- lease owner、期限、attempt、実行結果を監査可能な形で保存する。
- HTTP transport では認証、認可、TLS/信頼境界、session isolation、request size limit を明示する。
- credential、token、対象機密情報をログや MCP error に出さない。
- パス入力は resolve 後に許可 root 配下であることを検証する。
- `.env` や DB、artifact、秘密情報を Git に含めない。

## 環境変数（現行）

- `SONOBAT_DB_PATH`: SQLite DB path。既定値は `sonobat.db`
- `SONOBAT_DATA_DIR`: HackTricks 等の data root。既定値は `~/.sonobat/data/`

将来の HTTP/DB 選択用設定名は、実装と同時に定義し、README とこの文書を更新すること。
