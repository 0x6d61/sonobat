import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getDataDir, getHacktricksDir, ensureDataDir } from '../../src/engine/data-dir.js';

describe('data-dir', () => {
  const originalEnv = process.env['SONOBAT_DATA_DIR'];

  afterEach(() => {
    // Restore original env
    if (originalEnv === undefined) {
      delete process.env['SONOBAT_DATA_DIR'];
    } else {
      process.env['SONOBAT_DATA_DIR'] = originalEnv;
    }
  });

  // =========================================================
  // getDataDir
  // =========================================================

  describe('getDataDir', () => {
    it('デフォルトは ~/.sonobat/data/ を返す', () => {
      delete process.env['SONOBAT_DATA_DIR'];
      const result = getDataDir();
      const expected = path.join(os.homedir(), '.sonobat', 'data');
      expect(result).toBe(expected);
    });

    it('環境変数 SONOBAT_DATA_DIR でオーバーライドできる', () => {
      const customDir = path.join(os.tmpdir(), 'sonobat-test-data');
      process.env['SONOBAT_DATA_DIR'] = customDir;
      const result = getDataDir();
      expect(result).toBe(customDir);
    });
  });

  // =========================================================
  // getHacktricksDir
  // =========================================================

  describe('getHacktricksDir', () => {
    it('getDataDir() の下に hacktricks/ を返す', () => {
      delete process.env['SONOBAT_DATA_DIR'];
      const result = getHacktricksDir();
      const expected = path.join(os.homedir(), '.sonobat', 'data', 'hacktricks');
      expect(result).toBe(expected);
    });

    it('環境変数オーバーライドが反映される', () => {
      const customDir = path.join(os.tmpdir(), 'sonobat-test-data');
      process.env['SONOBAT_DATA_DIR'] = customDir;
      const result = getHacktricksDir();
      expect(result).toBe(path.join(customDir, 'hacktricks'));
    });
  });

  // =========================================================
  // ensureDataDir
  // =========================================================

  describe('ensureDataDir', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sonobat-ensure-test-'));
      process.env['SONOBAT_DATA_DIR'] = path.join(tmpDir, 'nested', 'data');
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('ディレクトリが存在しない場合は再帰的に作成する', () => {
      const dataDir = getDataDir();
      expect(fs.existsSync(dataDir)).toBe(false);

      ensureDataDir();
      expect(fs.existsSync(dataDir)).toBe(true);
      expect(fs.statSync(dataDir).isDirectory()).toBe(true);
    });

    it('ディレクトリが既に存在する場合はエラーにならない', () => {
      ensureDataDir();
      // 2回目もエラーにならない
      expect(() => ensureDataDir()).not.toThrow();
    });
  });
});
