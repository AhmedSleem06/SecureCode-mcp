import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execFileSync } from 'child_process';
import { getGitChangedFiles, formatGitChangedFiles } from '../src/utils/gitContext';

let workspaceRoot: string;
let oldCwd: string;

function git(args: string[], cwd: string): void {
    execFileSync('git', args, { cwd, stdio: 'pipe', timeout: 5000, windowsHide: true });
}

beforeAll(() => {
    workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-git-diff-'));
    oldCwd = process.cwd();

    git(['init'], workspaceRoot);
    git(['config', 'user.email', 'test@test.com'], workspaceRoot);
    git(['config', 'user.name', 'Test'], workspaceRoot);

    fs.writeFileSync(path.join(workspaceRoot, 'file1.ts'), 'export const a = 1;');
    fs.writeFileSync(path.join(workspaceRoot, 'file2.ts'), 'export const b = 2;');
    git(['add', '.'], workspaceRoot);
    git(['commit', '-m', 'initial'], workspaceRoot);

    fs.writeFileSync(path.join(workspaceRoot, 'file1.ts'), 'export const a = 2;');
    fs.writeFileSync(path.join(workspaceRoot, 'file3.ts'), 'export const c = 3;');
    git(['add', '.'], workspaceRoot);
    git(['commit', '-m', 'second'], workspaceRoot);
});

afterAll(() => {
    try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
});

describe('getGitChangedFiles', () => {
    it('returns changed files between two refs', async () => {
        const result = await getGitChangedFiles(workspaceRoot, 'HEAD~1');
        expect(result.ok).toBe(true);
        expect(result.files.length).toBeGreaterThan(0);
        expect(result.files).toContain('file1.ts');
    });

    it('returns empty for identical refs', async () => {
        const result = await getGitChangedFiles(workspaceRoot, 'HEAD');
        expect(result.ok).toBe(true);
        expect(result.files.length).toBe(0);
    });

    it('returns error for invalid ref', async () => {
        const result = await getGitChangedFiles(workspaceRoot, 'invalid..ref');
        expect(result.ok).toBe(false);
        expect(result.error).toContain('Invalid');
    });

    it('rejects refs with range operators', async () => {
        const result = await getGitChangedFiles(workspaceRoot, 'main..feature');
        expect(result.ok).toBe(false);
    });

    it('rejects refs with shell metacharacters', async () => {
        const result = await getGitChangedFiles(workspaceRoot, 'main; rm -rf /');
        expect(result.ok).toBe(false);
        expect(result.error).toContain('Invalid');
    });

    it('returns error for non-git workspace', async () => {
        const nonGit = fs.mkdtempSync(path.join(os.tmpdir(), 'non-git-'));
        try {
            const result = await getGitChangedFiles(nonGit, 'HEAD');
            expect(result.ok).toBe(false);
            expect(result.error).toContain('Not a git repository');
        } finally {
            fs.rmSync(nonGit, { recursive: true, force: true });
        }
    });
});

describe('formatGitChangedFiles', () => {
    it('formats changed files list', async () => {
        const formatted = await formatGitChangedFiles(workspaceRoot, 'HEAD~1');
        expect(formatted).toContain('Changed files');
        expect(formatted).toContain('file1.ts');
    });

    it('formats empty diff', async () => {
        const formatted = await formatGitChangedFiles(workspaceRoot, 'HEAD');
        expect(formatted).toContain('No files changed');
    });
});
