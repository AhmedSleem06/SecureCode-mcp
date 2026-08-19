import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { getCallGraph } from '../src/project-map/callGraphExtractor';

const TMP_DIR = path.join(__dirname, '..', '.tmp-callgraph-test');
const WORKSPACE = path.join(TMP_DIR, 'ws');

beforeAll(() => {
    fs.mkdirSync(WORKSPACE, { recursive: true });
});

afterAll(() => {
    try { fs.rmSync(TMP_DIR, { recursive: true, force: true }); } catch {}
});

function writeFile(rel: string, content: string): string {
    const abs = path.join(WORKSPACE, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, 'utf8');
    return rel.replace(/\\/g, '/');
}

describe('getCallGraph — security', () => {
    it('rejects path traversal attempts with supported extension (hits workspace confinement)', async () => {
        writeFile('src/safe.ts', 'export function foo() {}');
        const result = await getCallGraph(WORKSPACE, '../../../etc/passwd.ts');
        expect(result).toMatch(/Error reading file|outside the workspace/);
        expect(result).not.toContain('root:');
    });

    it('rejects path traversal attempts with unsupported extension (hits grammar check)', async () => {
        writeFile('src/safe.ts', 'export function foo() {}');
        const result = await getCallGraph(WORKSPACE, '../../../etc/passwd');
        expect(result).toContain('unsupported file type');
        expect(result).not.toContain('root:');
    });

    it('rejects absolute paths outside the workspace', async () => {
        writeFile('src/safe.ts', 'export function foo() {}');
        const outside = path.join(path.sep, 'tmp', 'outside-test.ts');
        const result = await getCallGraph(WORKSPACE, outside);
        expect(result).toMatch(/Error reading file|outside the workspace|unsupported/);
    });
});

describe('getCallGraph — file-level', () => {
    it('lists all functions and their callees', async () => {
        writeFile('src/module.ts', `
import { query } from './db';
export function handler(req: any) {
    return query(req.body);
}
function validate(input: string) {
    return input.length > 0;
}
`);
        const result = await getCallGraph(WORKSPACE, 'src/module.ts');
        expect(result).toContain('Call graph for src/module.ts');
        expect(result).toContain('handler');
        expect(result).toContain('validate');
        expect(result).toContain('query');
    });

    it('handles files with no functions', async () => {
        writeFile('src/empty.ts', 'const x = 42;');
        const result = await getCallGraph(WORKSPACE, 'src/empty.ts');
        expect(result).toContain('No functions found');
    });

    it('handles unsupported file types', async () => {
        writeFile('src/data.json', '{"a":1}');
        const result = await getCallGraph(WORKSPACE, 'src/data.json');
        expect(result).toContain('unsupported file type');
    });
});

describe('getCallGraph — function-level', () => {
    it('shows forward and reverse edges for a named function', async () => {
        writeFile('src/flow.ts', `
import { db } from './db';
export function createUser(input: string) {
    const validated = sanitize(input);
    return db.save(validated);
}
function sanitize(input: string) {
    return input.trim();
}
export function deleteUser(id: string) {
    return db.delete(id);
}
`);
        const result = await getCallGraph(WORKSPACE, 'src/flow.ts', 'createUser');
        expect(result).toContain('Function: createUser');
        expect(result).toContain('Callees');
        expect(result).toContain('sanitize');
        expect(result).toContain('db.save');
    });

    it('lists available functions when the target is not found', async () => {
        writeFile('src/missing.ts', `
export function foo() {}
export function bar() {}
`);
        const result = await getCallGraph(WORKSPACE, 'src/missing.ts', 'nonexistent');
        expect(result).toContain('not found');
        expect(result).toContain('foo');
        expect(result).toContain('bar');
    });
});

describe('getCallGraph — cross-file resolution', () => {
    it('resolves relative imports to workspace-relative paths', async () => {
        writeFile('src/db.ts', 'export function query(sql: string) { return []; }');
        writeFile('src/handler.ts', `
import { query } from './db';
export function handle(req: any) {
    return query(req.body.sql);
}
`);
        const result = await getCallGraph(WORKSPACE, 'src/handler.ts', 'handle');
        expect(result).toContain('query');
        expect(result).toContain('src/db.ts');
    });
});
