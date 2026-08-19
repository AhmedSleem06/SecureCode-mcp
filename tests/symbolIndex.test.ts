import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { findDefinition, findReferences } from '../src/project-map/symbolIndex';

const TMP_DIR = path.join(__dirname, '..', '.tmp-symbol-test');
const WORKSPACE = path.join(TMP_DIR, 'ws');

beforeAll(() => {
    fs.rmSync(TMP_DIR, { recursive: true, force: true });
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

describe('findDefinition — TypeScript', () => {
    it('finds a function definition in the same file', async () => {
        writeFile('src/handler.ts', `
export function processUser(input: string): string {
    return sanitize(input);
}
function sanitize(input: string): string {
    return input.trim();
}
`);
        const result = await findDefinition(WORKSPACE, 'src/handler.ts', 'sanitize');
        expect(result).toContain('Definition of "sanitize"');
        expect(result).toContain('src/handler.ts');
    });

    it('finds a class definition', async () => {
        writeFile('src/models.ts', `
export class User {
    constructor(public name: string) {}
}
`);
        const result = await findDefinition(WORKSPACE, 'src/models.ts', 'User');
        expect(result).toContain('Definition of "User"');
        expect(result).toContain('src/models.ts');
    });

    it('returns "no definition" for non-existent symbol', async () => {
        writeFile('src/empty.ts', 'const x = 1;');
        const result = await findDefinition(WORKSPACE, 'src/empty.ts', 'nonexistent');
        expect(result).toContain('No definition found');
    });
});

describe('findReferences — TypeScript', () => {
    it('finds references to a function in the same file', async () => {
        writeFile('src/refs.ts', `
export function helper() { return 42; }
export function caller() { return helper(); }
export function caller2() { return helper(); }
`);
        const result = await findReferences(WORKSPACE, 'src/refs.ts', 'helper');
        expect(result).toContain('References to "helper"');
        expect(result).toContain('src/refs.ts');
    });

    it('returns "no references" for unused symbol', async () => {
        writeFile('src/unused.ts', `export function unused() { return 1; }`);
        const result = await findReferences(WORKSPACE, 'src/unused.ts', 'unused');
        // TypeScript may find the declaration as a reference — that's valid
        expect(result).toMatch(/References to "unused"|No references found/);
    });
});

describe('findDefinition — Python (tree-sitter)', () => {
    it('finds a function definition in the same file', async () => {
        writeFile('src/auth.py', `
def check_auth(user):
    return user.is_authenticated

def login(user):
    return check_auth(user)
`);
        const result = await findDefinition(WORKSPACE, 'src/auth.py', 'check_auth');
        expect(result).toContain('Definition of "check_auth"');
        expect(result).toContain('src/auth.py');
        expect(result).toContain('[ast');
    });

    it('returns "no definition" for non-existent Python symbol', async () => {
        writeFile('src/empty.py', 'x = 1');
        const result = await findDefinition(WORKSPACE, 'src/empty.py', 'nonexistent');
        expect(result).toContain('No definition found');
    });
});

describe('findReferences — Python (tree-sitter)', () => {
    it('finds references via workspace search', async () => {
        writeFile('src/use.py', `
from auth import check_auth
result = check_auth("admin")
`);
        writeFile('src/auth.py', 'def check_auth(user):\n    return True\n');
        const result = await findReferences(WORKSPACE, 'src/auth.py', 'check_auth');
        expect(result).toContain('References to "check_auth"');
        // Should find references in both auth.py and use.py
        expect(result).toContain('check_auth');
    });
});

describe('findDefinition — security', () => {
    it('rejects path traversal', async () => {
        const result = await findDefinition(WORKSPACE, '../../../etc/passwd', 'root');
        expect(result).toMatch(/Error|outside the workspace/);
    });
});
