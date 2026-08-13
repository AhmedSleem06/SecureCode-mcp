// Vitest suite for searchCode — ripgrep/grep wrapper.
//
// Covers:
//   - formatSearchResult formats hits as path:line: text
//   - formatSearchResult returns "No matches found" on empty
//   - formatSearchResult notes truncation
//   - searchCode returns hits with path, line, text

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { formatSearchResult, searchCode, type SearchHit, type SearchResult } from '../src/utils/searchCode';

describe('formatSearchResult', () => {
    it('formats hits as path:line: text', () => {
        const result: SearchResult = {
            hits: [
                { path: 'src/handler.ts', line: 10, text: 'isProjectOwner(req)' },
                { path: 'src/auth.ts', line: 25, text: 'function isProjectOwner' },
            ],
            total: 2,
            truncated: false,
        };
        const formatted = formatSearchResult(result);
        expect(formatted).toContain('src/handler.ts:10: isProjectOwner(req)');
        expect(formatted).toContain('src/auth.ts:25: function isProjectOwner');
    });

    it('returns "No matches found" on empty results', () => {
        const formatted = formatSearchResult({ hits: [], total: 0, truncated: false });
        expect(formatted).toBe('No matches found.');
    });

    it('notes truncation when results are truncated', () => {
        const result: SearchResult = {
            hits: Array.from({ length: 50 }, (_, i) => ({ path: `f${i}.ts`, line: i + 1, text: 'match' })),
            total: 100,
            truncated: true,
        };
        const formatted = formatSearchResult(result);
        expect(formatted).toContain('100 total matches');
        expect(formatted).toContain('showing first 50');
    });
});

describe('searchCode (integration with real filesystem)', () => {
    let tmpDir: string;

    beforeAll(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'searchcode-test-'));
        fs.writeFileSync(path.join(tmpDir, 'handler.ts'), 'export function handler() {\n  const q = req.body.q;\n  db.query(q);\n}\n');
        fs.writeFileSync(path.join(tmpDir, 'auth.ts'), 'export function requireAuth() {\n  return jwt.verify(token);\n}\n');
        fs.mkdirSync(path.join(tmpDir, 'sub'));
        fs.writeFileSync(path.join(tmpDir, 'sub/utils.ts'), 'export function helper() {\n  // db.query here\n}\n');
    });

    afterAll(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('finds matches across multiple files', async () => {
        const result = await searchCode(tmpDir, 'db\\.query');
        expect(result.hits.length).toBeGreaterThanOrEqual(2);
        expect(result.hits.some(h => h.path.includes('handler.ts'))).toBe(true);
        expect(result.hits.some(h => h.path.includes('sub/utils.ts'))).toBe(true);
    });

    it('returns empty results for no matches', async () => {
        const result = await searchCode(tmpDir, 'this_pattern_does_not_exist_anywhere');
        expect(result.hits).toHaveLength(0);
        expect(result.total).toBe(0);
    });

    it('respects glob filter', async () => {
        const result = await searchCode(tmpDir, 'db\\.query', '*.ts');
        expect(result.hits.length).toBeGreaterThanOrEqual(1);
        // All hits should be .ts files
        expect(result.hits.every(h => h.path.endsWith('.ts'))).toBe(true);
    });

    it('includes line numbers in hits', async () => {
        const result = await searchCode(tmpDir, 'requireAuth');
        expect(result.hits.length).toBeGreaterThanOrEqual(1);
        expect(result.hits[0].line).toBeGreaterThan(0);
        expect(result.hits[0].text).toContain('requireAuth');
    });
});
