import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isGitAvailable, cloneHacktricks, pullHacktricks } from '../../src/engine/git-ops.js';

// =========================================================
// isGitAvailable
// =========================================================

describe('isGitAvailable', () => {
  it('git がインストールされている環境では true を返す', async () => {
    // CI/開発環境では git が利用可能なはず
    const result = await isGitAvailable();
    expect(result).toBe(true);
  });
});

// =========================================================
// cloneHacktricks — エラーケース
// =========================================================

describe('cloneHacktricks', () => {
  it('親ディレクトリが存在しない場合は clone_failed を返す', async () => {
    const nonExistentDir = path.join(
      os.tmpdir(),
      'sonobat-nonexistent-' + Date.now(),
      'deep',
      'nested',
      'hacktricks',
    );
    const result = await cloneHacktricks(nonExistentDir);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe('clone_failed');
    }
  });

  // 実際の clone テストはネットワーク依存なので統合テストに委譲
});

// =========================================================
// pullHacktricks — エラーケース
// =========================================================

describe('pullHacktricks', () => {
  it('ディレクトリが存在しない場合は directory_not_found を返す', async () => {
    const nonExistentDir = path.join(os.tmpdir(), 'sonobat-nonexistent-' + Date.now());
    const result = await pullHacktricks(nonExistentDir);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe('directory_not_found');
    }
  });

  it('.git がないディレクトリでは pull_failed を返す', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sonobat-nogit-'));
    try {
      const result = await pullHacktricks(tmpDir);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.kind).toBe('pull_failed');
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
