/**
 * sonobat — HackTricks Indexer Engine
 *
 * Parses Markdown files into searchable chunks and indexes them into
 * the technique_docs table with FTS5 full-text search.
 */

import type Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { TechniqueDocRepository } from '../db/repository/technique-doc-repository.js';
import type { CreateTechniqueDocInput } from '../types/repository.js';

/** A parsed chunk from a Markdown file. */
export interface MarkdownChunk {
  title: string;
  content: string;
  chunkIndex: number;
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
 * - Deletes existing documents from the 'hacktricks' source before re-indexing.
 * - Processes files sequentially to avoid excessive memory usage.
 * - Returns the total number of indexed chunks.
 */
export function indexHacktricks(db: Database.Database, hacktricksDir: string): number {
  const repo = new TechniqueDocRepository(db);

  // Remove existing hacktricks documents for re-indexing
  repo.deleteBySource(SOURCE_NAME);

  const mdFiles = collectMarkdownFiles(hacktricksDir, hacktricksDir);
  const allDocs: CreateTechniqueDocInput[] = [];

  for (const filePath of mdFiles) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const relativePath = path.relative(hacktricksDir, filePath).replace(/\\/g, '/');
    const category = extractCategory(relativePath);
    const chunks = parseMarkdownChunks(content, path.basename(filePath));

    for (const chunk of chunks) {
      allDocs.push({
        source: SOURCE_NAME,
        filePath: relativePath,
        title: chunk.title,
        category,
        content: chunk.content,
        chunkIndex: chunk.chunkIndex,
      });
    }
  }

  return repo.index(allDocs);
}
