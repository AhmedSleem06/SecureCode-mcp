import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { findTests } from '../src/project-map/findTests';

const TMP = path.join(__dirname, '.tmp-findTests');

function setupWorkspace(files: Record<string, string>): string {
    fs.rmSync(TMP, { recursive: true, force: true });
    fs.mkdirSync(TMP, { recursive: true });
    for (const [rel, content] of Object.entries(files)) {
        const abs = path.join(TMP, rel);
        fs.mkdirSync(path.dirname(abs), { recursive: true });
        fs.writeFileSync(abs, content);
    }
    return TMP;
}

describe('findTests', () => {
    afterEach(() => {
        fs.rmSync(TMP, { recursive: true, force: true });
    });

    describe('naming convention — JS/TS', () => {
        it('finds test file in tests/ directory', async () => {
            const ws = setupWorkspace({
                'src/auth.ts': 'export function login() {}',
                'tests/auth.test.ts': 'import { login } from "../src/auth"; test("login", () => {});',
            });
            const result = await findTests(ws, 'src/auth.ts');
            expect(result).toContain('tests/auth.test.ts');
            expect(result).toContain('By naming convention');
        });

        it('finds test file in same directory as source', async () => {
            const ws = setupWorkspace({
                'src/utils/crypto.ts': 'export function hash() {}',
                'src/utils/crypto.test.ts': 'test("hash", () => {});',
            });
            const result = await findTests(ws, 'src/utils/crypto.ts');
            expect(result).toContain('crypto.test.ts');
            expect(result).toContain('By naming convention');
        });

        it('finds .spec.ts files', async () => {
            const ws = setupWorkspace({
                'src/handler.ts': 'export function handle() {}',
                '__tests__/handler.spec.ts': 'test("handle", () => {});',
            });
            const result = await findTests(ws, 'src/handler.ts');
            expect(result).toContain('handler.spec.ts');
        });

        it('deduplicates test files found in multiple locations', async () => {
            const ws = setupWorkspace({
                'src/app.ts': 'export function app() {}',
                'tests/app.test.ts': 'test("app", () => {});',
            });
            const result = await findTests(ws, 'src/app.ts');
            const matches = result.match(/app\.test\.ts/g);
            expect(matches).not.toBeNull();
            expect(matches!.length).toBe(1);
        });
    });

    describe('naming convention — Python', () => {
        it('finds test_foo.py in tests/ directory', async () => {
            const ws = setupWorkspace({
                'src/auth.py': 'def login(): pass',
                'tests/test_auth.py': 'def test_login(): pass',
            });
            const result = await findTests(ws, 'src/auth.py');
            expect(result).toContain('test_auth.py');
            expect(result).toContain('By naming convention');
        });

        it('finds test file in same directory', async () => {
            const ws = setupWorkspace({
                'src/utils/helpers.py': 'def helper(): pass',
                'src/utils/test_helpers.py': 'def test_helper(): pass',
            });
            const result = await findTests(ws, 'src/utils/helpers.py');
            expect(result).toContain('test_helpers.py');
        });
    });

    describe('symbol reference search', () => {
        it('finds test files referencing a symbol', async () => {
            const ws = setupWorkspace({
                'src/lib/auth.ts': 'export function requireAuth() {}',
                'tests/auth.test.ts': 'import { requireAuth } from "../src/lib/auth"; test("auth", () => { requireAuth(); });',
                'tests/integration.test.ts': 'test("integration", () => { requireAuth(); });',
            });
            const result = await findTests(ws, 'src/lib/auth.ts', 'requireAuth');
            expect(result).toContain('By symbol reference');
            expect(result).toContain('requireAuth');
        });

        it('does not report naming-match files as symbol matches', async () => {
            const ws = setupWorkspace({
                'src/auth.ts': 'export function login() {}',
                'tests/auth.test.ts': 'import { login } from "../src/auth"; test("login", () => { login(); });',
            });
            const result = await findTests(ws, 'src/auth.ts', 'login');
            expect(result).toContain('tests/auth.test.ts');
            // Should be listed under naming convention, not symbol reference
            const namingSection = result.split('By symbol reference')[0];
            expect(namingSection).toContain('By naming convention');
        });

        it('returns matched line previews for symbol matches', async () => {
            const ws = setupWorkspace({
                'src/guard.ts': 'export function checkGuard() {}',
                'tests/guard.test.ts': 'test("guard", () => { checkGuard(); });',
            });
            const result = await findTests(ws, 'src/guard.ts', 'checkGuard');
            expect(result).toContain('checkGuard');
        });
    });

    describe('edge cases', () => {
        it('returns message when no tests found', async () => {
            const ws = setupWorkspace({
                'src/lonely.ts': 'export function alone() {}',
            });
            const result = await findTests(ws, 'src/lonely.ts');
            expect(result).toContain('No test files found');
        });

        it('returns message when source file not found', async () => {
            const ws = setupWorkspace({});
            const result = await findTests(ws, 'src/nonexistent.ts');
            expect(result).toContain('Source file not found');
        });

        it('rejects path traversal', async () => {
            const ws = setupWorkspace({
                'src/auth.ts': 'export function login() {}',
            });
            const result = await findTests(ws, '../../../etc/passwd');
            expect(result).toContain('Error');
            expect(result).toContain('outside the workspace');
        });

        it('returns message when no tests found for symbol', async () => {
            const ws = setupWorkspace({
                'src/auth.ts': 'export function login() {}',
                'tests/auth.test.ts': 'test("login", () => {});',
            });
            const result = await findTests(ws, 'src/auth.ts', 'nonexistentSymbol');
            // Should still find the naming-convention match
            expect(result).toContain('tests/auth.test.ts');
            expect(result).toContain('By naming convention');
        });
    });
});
