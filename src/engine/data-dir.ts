/**
 * sonobat — Data Directory Utilities
 *
 * Manages the default data directory (~/.sonobat/data/) where HackTricks
 * and other data sources are stored. Supports overriding via environment
 * variable SONOBAT_DATA_DIR for testing and custom setups.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Get the root data directory path.
 * Default: ~/.sonobat/data/
 * Override: set SONOBAT_DATA_DIR environment variable.
 */
export function getDataDir(): string {
  const envDir = process.env['SONOBAT_DATA_DIR'];
  if (envDir) return envDir;
  return path.join(os.homedir(), '.sonobat', 'data');
}

/**
 * Get the HackTricks repository directory path.
 * Returns: <dataDir>/hacktricks/
 */
export function getHacktricksDir(): string {
  return path.join(getDataDir(), 'hacktricks');
}

/**
 * Ensure the data directory exists, creating it recursively if needed.
 */
export function ensureDataDir(): void {
  fs.mkdirSync(getDataDir(), { recursive: true });
}
