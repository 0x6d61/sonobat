/**
 * sonobat — Git Operations for HackTricks
 *
 * Provides git clone/pull operations for managing the HackTricks repository.
 * Uses execFile (not shell) to prevent command injection.
 */

import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';

const execFile = promisify(execFileCb);

const HACKTRICKS_REPO = 'https://github.com/HackTricks-wiki/hacktricks.git';
const TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

/** Error kinds for git operations. */
export type GitErrorKind =
  | 'git_not_found'
  | 'clone_failed'
  | 'pull_failed'
  | 'permission_denied'
  | 'network_error'
  | 'directory_not_found'
  | 'unknown';

/** Result type for git operations. */
export type GitResult =
  | { ok: true; message: string }
  | { ok: false; error: { kind: GitErrorKind; message: string; cause?: string } };

/**
 * Check if git is available on the system PATH.
 */
export async function isGitAvailable(): Promise<boolean> {
  try {
    await execFile('git', ['--version'], { timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Classify an error from execFile into a GitErrorKind.
 */
function classifyError(err: unknown, operation: 'clone' | 'pull'): GitResult {
  const errorMessage = err instanceof Error ? err.message : String(err);
  const stderr =
    err !== null && typeof err === 'object' && 'stderr' in err
      ? String((err as { stderr: unknown }).stderr)
      : '';

  const combined = `${errorMessage} ${stderr}`.toLowerCase();

  if (
    combined.includes('enoent') ||
    combined.includes('not recognized') ||
    combined.includes('not found')
  ) {
    return {
      ok: false,
      error: {
        kind: 'git_not_found',
        message: 'git is not installed or not in PATH',
        cause: errorMessage,
      },
    };
  }

  if (combined.includes('permission denied') || combined.includes('access denied')) {
    return {
      ok: false,
      error: {
        kind: 'permission_denied',
        message: `Permission denied during ${operation}`,
        cause: errorMessage,
      },
    };
  }

  if (
    combined.includes('could not resolve') ||
    combined.includes('unable to access') ||
    combined.includes('network') ||
    combined.includes('timed out')
  ) {
    return {
      ok: false,
      error: {
        kind: 'network_error',
        message: `Network error during ${operation}`,
        cause: errorMessage,
      },
    };
  }

  return {
    ok: false,
    error: {
      kind: operation === 'clone' ? 'clone_failed' : 'pull_failed',
      message: `git ${operation} failed`,
      cause: errorMessage,
    },
  };
}

/**
 * Clone the HackTricks repository with --depth 1 (shallow clone).
 * The targetDir is the destination directory for the clone.
 * The parent directory of targetDir must exist.
 */
export async function cloneHacktricks(targetDir: string): Promise<GitResult> {
  // Check parent directory exists before attempting clone
  const parentDir = path.dirname(targetDir);

  if (!fs.existsSync(parentDir)) {
    return {
      ok: false,
      error: {
        kind: 'clone_failed',
        message: `Parent directory does not exist: ${parentDir}`,
      },
    };
  }

  try {
    const { stdout } = await execFile(
      'git',
      ['clone', '--depth', '1', HACKTRICKS_REPO, targetDir],
      { timeout: TIMEOUT_MS },
    );
    return { ok: true, message: stdout.trim() || 'Clone completed successfully' };
  } catch (err) {
    return classifyError(err, 'clone');
  }
}

/**
 * Pull latest changes in an existing HackTricks repository.
 * Uses --ff-only to avoid merge conflicts.
 */
export async function pullHacktricks(repoDir: string): Promise<GitResult> {
  // Check if directory exists
  if (!fs.existsSync(repoDir)) {
    return {
      ok: false,
      error: {
        kind: 'directory_not_found',
        message: `Directory not found: ${repoDir}`,
      },
    };
  }

  try {
    const { stdout } = await execFile('git', ['pull', '--ff-only'], {
      cwd: repoDir,
      timeout: TIMEOUT_MS,
    });
    return { ok: true, message: stdout.trim() || 'Already up to date' };
  } catch (err) {
    return classifyError(err, 'pull');
  }
}
