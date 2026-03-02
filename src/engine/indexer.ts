/**
 * sonobat — HackTricks Indexer Engine
 *
 * Parses Markdown files into searchable chunks and indexes them into
 * the technique_docs table with FTS5 full-text search.
 * Supports incremental indexing by comparing file mtimes.
 */

import type Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { TechniqueDocRepository } from '../db/repository/technique-doc-repository.js';
import type { CreateTechniqueDocInput } from '../db/repository/technique-doc-repository.js';

/** A parsed chunk from a Markdown file. */
export interface MarkdownChunk {
  title: string;
  content: string;
  chunkIndex: number;
}

/** Result of an indexing operation. */
export interface IndexResult {
  totalChunks: number;
  newFiles: number;
  updatedFiles: number;
  deletedFiles: number;
  skippedFiles: number;
}

/**
 * Parse a Markdown file into chunks split by H2 boundaries.
 *
 * - H1 (`# Title`) is extracted as the document title (falls back to filename).
 * - Content is split at H2 (`## Section`) boundaries.
 * - Each chunk is an independent search unit.
 * - If no H2 is present, the entire content is one chunk.
 * - Empty/whitespace-only content returns an empty array.
 */
export function parseMarkdownChunks(markdown: string, fileName: string): MarkdownChunk[] {
  const trimmed = markdown.trim();
  if (trimmed.length === 0) return [];

  const lines = trimmed.split('\n');

  // Extract H1 title
  let title: string | undefined;
  let contentStartIndex = 0;

  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/^#\s+(.+)$/);
    if (match) {
      title = match[1].trim();
      contentStartIndex = i + 1;
      break;
    }
  }

  if (!title) {
    // Use filename without extension as title
    title = path.basename(fileName, path.extname(fileName));
    contentStartIndex = 0;
  }

  const contentLines = lines.slice(contentStartIndex);

  // Split by H2 boundaries
  const sections: Array<{ heading: string | null; lines: string[] }> = [];
  let currentSection: { heading: string | null; lines: string[] } = { heading: null, lines: [] };

  for (const line of contentLines) {
    const h2Match = line.match(/^##\s+(.+)$/);
    if (h2Match) {
      // Save current section if it has content
      sections.push(currentSection);
      currentSection = { heading: h2Match[1].trim(), lines: [] };
    } else {
      currentSection.lines.push(line);
    }
  }
  sections.push(currentSection);

  // Build chunks
  const chunks: MarkdownChunk[] = [];
  let chunkIndex = 0;

  for (const section of sections) {
    const sectionContent = section.heading
      ? `## ${section.heading}\n\n${section.lines.join('\n').trim()}`
      : section.lines.join('\n').trim();

    if (sectionContent.length === 0) continue;

    chunks.push({
      title,
      content: sectionContent,
      chunkIndex,
    });
    chunkIndex++;
  }

  return chunks;
}

/**
 * Extract category from a file path (relative to the root directory).
 * Category is the directory portion of the path using forward slashes.
 *
 * Examples:
 *   "linux-hardening/privilege-escalation/docker-breakout.md" → "linux-hardening/privilege-escalation"
 *   "web/sql-injection.md" → "web"
 *   "README.md" → ""
 */
export function extractCategory(filePath: string): string {
  // Normalize Windows backslashes to forward slashes
  const normalized = filePath.replace(/\\/g, '/');
  const dir = path.posix.dirname(normalized);
  return dir === '.' ? '' : dir;
}

/**
 * Recursively collect all .md files from a directory.
 */
function collectMarkdownFiles(dir: string, baseDir: string): string[] {
  const files: string[] = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectMarkdownFiles(fullPath, baseDir));
    } else if (entry.isFile() && entry.name.endsWith('.md')) {
      // Skip README files
      if (entry.name.toLowerCase() === 'readme.md') continue;
      files.push(fullPath);
    }
  }

  return files;
}

const SOURCE_NAME = 'hacktricks';

/**
 * Index all Markdown files from a HackTricks directory into the database.
 *
 * Uses incremental indexing:
 * 1. Fetches existing file_path → file_mtime map from DB
 * 2. Compares with disk files to classify: new, updated, deleted, unchanged
 * 3. Only processes new/updated files; deletes removed files from DB
 *
 * Returns an IndexResult with statistics about what was processed.
 */
export function indexHacktricks(db: Database.Database, hacktricksDir: string): IndexResult {
  const repo = new TechniqueDocRepository(db);

  // Step 1: Get existing mtimes from DB
  const existingMtimes = repo.findMtimesBySource(SOURCE_NAME);

  // Step 2: Collect current files on disk and their mtimes
  const mdFiles = collectMarkdownFiles(hacktricksDir, hacktricksDir);
  const diskFiles = new Map<string, string>(); // relativePath → mtime ISO string

  for (const filePath of mdFiles) {
    const relativePath = path.relative(hacktricksDir, filePath).replace(/\\/g, '/');
    const stat = fs.statSync(filePath);
    diskFiles.set(relativePath, stat.mtime.toISOString());
  }

  // Step 3: Classify files
  const newFiles: string[] = [];
  const updatedFiles: string[] = [];
  const skippedFiles: string[] = [];

  for (const [relativePath, diskMtime] of diskFiles) {
    const existingMtime = existingMtimes.get(relativePath);
    if (existingMtime === undefined) {
      // Not in DB → new file
      newFiles.push(relativePath);
    } else if (existingMtime !== diskMtime) {
      // In DB but mtime changed → updated file
      updatedFiles.push(relativePath);
    } else {
      // Same mtime → skip
      skippedFiles.push(relativePath);
    }
  }

  // Deleted files: in DB but not on disk
  const deletedFiles: string[] = [];
  for (const existingPath of existingMtimes.keys()) {
    if (!diskFiles.has(existingPath)) {
      deletedFiles.push(existingPath);
    }
  }

  // Step 4: Delete changed/removed files from DB
  const filesToDelete = [...updatedFiles, ...deletedFiles];
  if (filesToDelete.length > 0) {
    repo.deleteBySourceAndFilePaths(SOURCE_NAME, filesToDelete);
  }

  // Step 5: Parse and insert new/updated files
  const filesToInsert = [...newFiles, ...updatedFiles];
  const allDocs: CreateTechniqueDocInput[] = [];

  for (const relativePath of filesToInsert) {
    const fullPath = path.join(hacktricksDir, relativePath);
    const content = fs.readFileSync(fullPath, 'utf-8');
    const category = extractCategory(relativePath);
    const chunks = parseMarkdownChunks(content, path.basename(fullPath));
    const fileMtime = diskFiles.get(relativePath)!;

    for (const chunk of chunks) {
      allDocs.push({
        source: SOURCE_NAME,
        filePath: relativePath,
        title: chunk.title,
        category,
        content: chunk.content,
        chunkIndex: chunk.chunkIndex,
        fileMtime,
      });
    }
  }

  const insertedChunks = repo.index(allDocs);

  return {
    totalChunks: insertedChunks,
    newFiles: newFiles.length,
    updatedFiles: updatedFiles.length,
    deletedFiles: deletedFiles.length,
    skippedFiles: skippedFiles.length,
  };
}
