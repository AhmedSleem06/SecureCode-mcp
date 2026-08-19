import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { getGitBlame, getGitHistory } from '../src/utils/gitContext';

const TMP_DIR = path.join(__dirname, '..', '.tmp-git-test');
const GIT_WORKSPACE = path.join(TMP_DIR, 'git-ws');
const SYSTEM_TEMP = require('os').tmpdir();
const NON_GIT_WORKSPACE = path.join(SYSTEM_TEMP, 'opencode', 'non-git-ws');

function git(args: string[], cwd: string): void {
    execFileSync('git', args, { cwd, timeout: 5000, windowsHide: true, stdio: 'pipe' });
}

beforeAll(() => {
    fs.rmSync(TMP_DIR, { recursive: true, force: true });
    fs.mkdirSync(GIT_WORKSPACE, { recursive: true });
    fs.mkdirSync(NON_GIT_WORKSPACE, { recursive: true });

    git(['init'], GIT_WORKSPACE);
    git(['config', 'user.email', 'author@example.com'], GIT_WORKSPACE);
    git(['config', 'user.name', 'Test Author'], GIT_WORKSPACE);

    fs.writeFileSync(path.join(GIT_WORKSPACE, 'app.ts'), 'export function handler() { return 42; }\n');
    git(['add', 'app.ts'], GIT_WORKSPACE);
    git(['commit', '-m', 'Initial commit with handler'], GIT_WORKSPACE);

    fs.writeFileSync(path.join(GIT_WORKSPACE, 'app.ts'), 'export function handler() { return query(input); }\n');
    git(['add', 'app.ts'], GIT_WORKSPACE);
    git(['commit', '-m', 'Add query call to handler'], GIT_WORKSPACE);
});

afterAll(() => {
    try { fs.rmSync(TMP_DIR, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(NON_GIT_WORKSPACE, { recursive: true, force: true }); } catch {}
});

describe('getGitBlame', () => {
    it('returns "not a git repo" for non-git workspaces', async () => {
        fs.writeFileSync(path.join(NON_GIT_WORKSPACE, 'file.ts'), 'const x = 1;');
        const result = await getGitBlame(NON_GIT_WORKSPACE, 'file.ts');
        expect(result).toContain('Not a git repository');
    });

    it('returns blame data for a tracked file', async () => {
        const result = await getGitBlame(GIT_WORKSPACE, 'app.ts');
        expect(result).toContain('Git blame');
        expect(result).toContain('handler');
    });

    it('redacts author email addresses', async () => {
        const result = await getGitBlame(GIT_WORKSPACE, 'app.ts');
        expect(result).not.toContain('author@example.com');
        expect(result).toContain('redacted');
    });

    it('rejects path traversal', async () => {
        const result = await getGitBlame(GIT_WORKSPACE, '../../../etc/passwd');
        expect(result).toMatch(/Error|outside the workspace/);
    });
});

describe('getGitHistory', () => {
    it('returns "not a git repo" for non-git workspaces', async () => {
        const result = await getGitHistory(NON_GIT_WORKSPACE);
        expect(result).toContain('Not a git repository');
    });

    it('returns commit history for the repo', async () => {
        const result = await getGitHistory(GIT_WORKSPACE);
        expect(result).toContain('Git history');
        expect(result).toContain('Initial commit');
        expect(result).toContain('Add query call');
    });

    it('returns history for a specific file', async () => {
        const result = await getGitHistory(GIT_WORKSPACE, 'app.ts');
        expect(result).toContain('Git history');
        expect(result).toContain('app.ts');
        expect(result).toContain('Initial commit');
    });

    it('redacts author email in history output', async () => {
        const result = await getGitHistory(GIT_WORKSPACE);
        expect(result).not.toContain('author@example.com');
    });

    it('respects the limit parameter', async () => {
        const result = await getGitHistory(GIT_WORKSPACE, undefined, undefined, 1);
        const lines = result.split('\n').filter(l => l.startsWith('  ') && !l.startsWith('    '));
        expect(lines.length).toBeLessThanOrEqual(1);
    });

    it('rejects path traversal', async () => {
        const result = await getGitHistory(GIT_WORKSPACE, '../../../etc/passwd');
        expect(result).toMatch(/Error|outside the workspace/);
    });

    it('returns "no history" for a non-existent file', async () => {
        const result = await getGitHistory(GIT_WORKSPACE, 'nonexistent.ts');
        expect(result).toContain('No commit history');
    });
});
