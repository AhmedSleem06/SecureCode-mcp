import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { toolScanSecrets } from '../src/tools/scanSecrets';
import { detectSecrets } from '../src/utils/secretDetector';
import type { ServerContext } from '../src/mcp/types';

const TMP = path.join(__dirname, '.tmp-scan-secrets-test');

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

function cleanup() {
    fs.rmSync(TMP, { recursive: true, force: true });
}

const CTX = (workspaceRoot: string): ServerContext => ({
    apiUrl: 'http://localhost:3000',
    apiToken: 'test-token',
    workspaceRoot,
});

// ── detectSecrets unit tests ──────────────────────────────────────────────

describe('detectSecrets', () => {
    it('detects JWT tokens', () => {
        const findings = detectSecrets('const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";');
        expect(findings.find(f => f.type === 'jwt')).toBeDefined();
        expect(findings.find(f => f.type === 'jwt')!.severity).toBe('CRITICAL');
    });

    it('detects AWS key IDs', () => {
        const findings = detectSecrets('const awsKey = "AKIAIOSFODNN7EXAMPLE";');
        expect(findings.find(f => f.type === 'aws_key_id')).toBeDefined();
    });

    it('detects GitHub PATs', () => {
        const findings = detectSecrets('const token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB";');
        expect(findings.find(f => f.type === 'github_pat')).toBeDefined();
    });

    it('detects env secrets', () => {
        const findings = detectSecrets('DB_PASSWORD=supersecret123');
        expect(findings.find(f => f.type === 'env_secret')).toBeDefined();
    });

    it('detects emails as MEDIUM PII', () => {
        const findings = detectSecrets('const admin = "admin@example.com";');
        const email = findings.find(f => f.type === 'email');
        expect(email).toBeDefined();
        expect(email!.severity).toBe('MEDIUM');
    });

    it('returns empty for clean code', () => {
        expect(detectSecrets('const x = 42;')).toEqual([]);
    });
});

// ── toolScanSecrets — directory scan ─────────────────────────────────────

describe('securecode.scan-secrets', () => {
    afterEach(cleanup);

    it('scans a directory and finds secrets', async () => {
        setupWorkspace({
            'src/app.ts': 'const apiKey = "sk-live-abc123def456ghi789jkl012mno345pqr678";',
            'src/config.ts': 'JWT_SECRET=mysupersecretkey123456',
            'src/clean.ts': 'const x = 42;',
        });

        const result = await toolScanSecrets(CTX(TMP), { directory: 'src' }) as any;

        expect(result.filesScanned).toBe(3);
        expect(result.totalFindings).toBeGreaterThan(0);
        expect(result.results.length).toBe(2);
        expect(result.results.find((r: any) => r.filePath === 'src/app.ts')).toBeDefined();
        expect(result.results.find((r: any) => r.filePath === 'src/config.ts')).toBeDefined();
        expect(result.results.find((r: any) => r.filePath === 'src/clean.ts')).toBeUndefined();
    });

    it('scans explicit filePaths', async () => {
        setupWorkspace({
            'a.ts': 'const key = "AKIAIOSFODNN7EXAMPLE";',
            'b.ts': 'const clean = 42;',
        });

        const result = await toolScanSecrets(CTX(TMP), {
            filePaths: ['a.ts', 'b.ts'],
        }) as any;

        expect(result.filesScanned).toBe(2);
        expect(result.results.length).toBe(1);
        expect(result.results[0].filePath).toBe('a.ts');
    });

    it('skips secret files (.env)', async () => {
        setupWorkspace({
            '.env': 'SECRET_KEY=supersecret123456',
            'app.ts': 'const clean = "no secrets here";',
        });

        const result = await toolScanSecrets(CTX(TMP), { directory: '.' }) as any;

        expect(result.skipped.find((s: any) => s.path === '.env' && s.reason === 'secret_file')).toBeDefined();
        expect(result.results.find((r: any) => r.filePath === '.env')).toBeUndefined();
    });

    it('respects .securecodeignore', async () => {
        setupWorkspace({
            '.securecodeignore': 'vendor/\n*.test.ts',
            'app.ts': 'const key = "AKIAIOSFODNN7EXAMPLE";',
            'vendor/lib.ts': 'const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB";',
            'file.test.ts': 'const x = "sk-live-abc123def456ghi789jkl012mno345pqr678";',
        });

        const result = await toolScanSecrets(CTX(TMP), { directory: '.' }) as any;

        expect(result.results.find((r: any) => r.filePath === 'app.ts')).toBeDefined();
        expect(result.results.find((r: any) => r.filePath.includes('vendor/'))).toBeUndefined();
        expect(result.results.find((r: any) => r.filePath.endsWith('.test.ts'))).toBeUndefined();
    });

    it('respects maxFiles cap', async () => {
        const files: Record<string, string> = {};
        for (let i = 0; i < 10; i++) {
            files[`file${i}.ts`] = `const key${i} = "AKIAIOSFODNN7EXAMPLE${i}";`;
        }
        setupWorkspace(files);

        const result = await toolScanSecrets(CTX(TMP), {
            directory: '.',
            maxFiles: 3,
        }) as any;

        expect(result.filesScanned + result.filesSkipped).toBeLessThanOrEqual(3);
    });

    it('reports progress via callback', async () => {
        setupWorkspace({
            'a.ts': 'const x = 42;',
            'b.ts': 'const y = 99;',
        });

        const calls: Array<[number, number, string]> = [];
        await toolScanSecrets(CTX(TMP), {
            directory: '.',
            _progress: (p: number, t: number, msg: string) => calls.push([p, t, msg]),
        });

        expect(calls.length).toBeGreaterThan(0);
        expect(calls[0][1]).toBe(2);
    });

    it('errors on missing directory and filePaths', async () => {
        await expect(toolScanSecrets(CTX(TMP), {})).rejects.toThrow();
    });

    it('errors on non-existent directory', async () => {
        await expect(toolScanSecrets(CTX(TMP), { directory: 'nonexistent' })).rejects.toThrow();
    });

    it('skips files larger than 1MB', async () => {
        const big = 'x'.repeat(1024 * 1024 + 100);
        setupWorkspace({
            'big.ts': big,
            'small.ts': 'const key = "AKIAIOSFODNN7EXAMPLE";',
        });

        const result = await toolScanSecrets(CTX(TMP), { directory: '.' }) as any;

        expect(result.skipped.find((s: any) => s.reason === 'too_large')).toBeDefined();
        expect(result.results.find((r: any) => r.filePath === 'small.ts')).toBeDefined();
    });

    it('aggregates findings by type and severity', async () => {
        setupWorkspace({
            'a.ts': 'const aws = "AKIAIOSFODNN7EXAMPLE";',
            'b.ts': 'const email = "admin@example.com";',
        });

        const result = await toolScanSecrets(CTX(TMP), { directory: '.' }) as any;

        expect(result.findingsByType.aws_key_id).toBe(1);
        expect(result.findingsByType.email).toBe(1);
        expect(result.findingsBySeverity.CRITICAL).toBe(1);
        expect(result.findingsBySeverity.MEDIUM).toBe(1);
    });
});
