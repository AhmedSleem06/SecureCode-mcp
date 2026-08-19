import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { readSecurityConfig } from '../src/utils/securityConfig';

const TMP_DIR = path.join(__dirname, '..', '.tmp-config-test');
const WORKSPACE = path.join(TMP_DIR, 'ws');

beforeAll(() => {
    fs.rmSync(TMP_DIR, { recursive: true, force: true });
    fs.mkdirSync(WORKSPACE, { recursive: true });
});

afterAll(() => {
    try { fs.rmSync(TMP_DIR, { recursive: true, force: true }); } catch {}
});

function writeFile(rel: string, content: string): void {
    const abs = path.join(WORKSPACE, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, 'utf8');
}

describe('readSecurityConfig', () => {
    it('returns "no config found" when no config files exist', async () => {
        const result = await readSecurityConfig(WORKSPACE, 'all');
        expect(result).toContain('No');
        expect(result).toContain('security config');
    });

    it('reads .env.example and shows keys without values', async () => {
        writeFile('.env.example', 'JWT_SECRET=dev-secret\nDATABASE_URL=postgres://localhost\ndebug=true');
        const result = await readSecurityConfig(WORKSPACE, 'env');
        expect(result).toContain('.env.example');
        expect(result).toContain('JWT_SECRET=REDACTED');
        expect(result).toContain('DATABASE_URL=set');
        expect(result).toContain('debug=set');
        expect(result).not.toContain('dev-secret');
        expect(result).not.toContain('postgres://localhost');
    });

    it('redacts secret values in .env files', async () => {
        writeFile('.env', 'API_KEY=sk-1234567890\nPORT=3000');
        const result = await readSecurityConfig(WORKSPACE, 'env');
        expect(result).toContain('API_KEY=REDACTED');
        expect(result).toContain('PORT=set');
        expect(result).not.toContain('sk-1234567890');
        expect(result).not.toContain('3000');
    });

    it('reads Next.js config for headers/CSP', async () => {
        writeFile('next.config.js', 'module.exports = { headers: { "Content-Security-Policy": "default-src \'self\'" } }');
        const result = await readSecurityConfig(WORKSPACE, 'headers');
        expect(result).toContain('next.config.js');
        expect(result).toContain('Content-Security-Policy');
    });

    it('filters by config kind', async () => {
        writeFile('.env.example', 'DEBUG=true');
        writeFile('helmet.config.js', 'module.exports = { contentSecurityPolicy: {} }');
        const envResult = await readSecurityConfig(WORKSPACE, 'env');
        expect(envResult).toContain('.env.example');
        expect(envResult).not.toContain('helmet.config.js');
        const headersResult = await readSecurityConfig(WORKSPACE, 'headers');
        expect(headersResult).toContain('helmet.config.js');
        expect(headersResult).not.toContain('.env.example');
    });

    it('returns "all" config when kind is "all"', async () => {
        writeFile('.env.example', 'DEBUG=true');
        writeFile('helmet.config.js', 'module.exports = {}');
        const result = await readSecurityConfig(WORKSPACE, 'all');
        expect(result).toContain('.env.example');
        expect(result).toContain('helmet.config.js');
    });

    it('preserves comment lines in .env files', async () => {
        writeFile('.env.example', '# This is a comment\nKEY=value');
        const result = await readSecurityConfig(WORKSPACE, 'env');
        expect(result).toContain('# This is a comment');
    });
});
