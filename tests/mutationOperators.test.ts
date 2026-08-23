import { describe, it, expect } from 'vitest';
import { applyMutation } from '../src/attack/mutationOperators';

describe('applyMutation', () => {
    it('adds auth guard for broken_access_control', () => {
        const code = 'function handler(req, res) {\n  res.json({ data });\n}';
        const result = applyMutation(code, 'broken_access_control', 2);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('isAuthenticated');
        expect(result.mutatedCode).toContain('403');
    });

    it('adds auth guard for missing_auth', () => {
        const code = 'function handler(req, res) {\n  res.json({ data });\n}';
        const result = applyMutation(code, 'missing_auth', 2);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('isAuthenticated');
    });

    it('adds ownership check for missing_ownership', () => {
        const code = 'async function getProject(req, res) {\n  return db.query();\n}';
        const result = applyMutation(code, 'missing_ownership', 2);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('ownerId');
        expect(result.mutatedCode).toContain('not owner');
    });

    it('replaces SQL interpolation with placeholders', () => {
        const code = 'const q = `SELECT * FROM users WHERE id = ${userId}`;';
        const result = applyMutation(code, 'sql_injection', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('?');
        expect(result.mutatedCode).not.toContain('${userId}');
    });

    it('adds path containment validation for path_traversal', () => {
        const code = 'const filePath = path.join(baseDir, userInput);\nfs.readFile(filePath);';
        const result = applyMutation(code, 'path_traversal', 2);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('path traversal blocked');
    });

    it('adds HTML escaping for xss', () => {
        const code = 'res.send(userInput);';
        const result = applyMutation(code, 'xss', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('script');
    });

    it('adds URL allowlist for ssrf', () => {
        const code = 'const resp = await fetch(targetUrl);';
        const result = applyMutation(code, 'ssrf', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('SSRF blocked');
    });

    it('adds input validation for missing_input_validation', () => {
        const code = 'function process(input) {\n  return input.trim();\n}';
        const result = applyMutation(code, 'missing_input_validation', 2);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('invalid input');
    });

    it('replaces hardcoded secret with env var', () => {
        const code = 'const apiKey = "sk-1234567890abcdef";';
        const result = applyMutation(code, 'secrets_in_source', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('process.env.SECRET_KEY');
    });

    it('returns not mutated for unknown vulnerability type', () => {
        const code = 'function handler() {}';
        const result = applyMutation(code, 'unknown_type', 1);
        expect(result.mutated).toBe(false);
        expect(result.description).toContain('No mutation operator');
    });

    it('returns not mutated when no SQL interpolation is found', () => {
        const code = 'const q = "SELECT * FROM users";';
        const result = applyMutation(code, 'sql_injection', 1);
        expect(result.mutated).toBe(false);
    });

    it('preserves indentation of the target line', () => {
        const code = 'function handler() {\n  if (true) {\n    doSomething();\n  }\n}';
        const result = applyMutation(code, 'missing_auth', 3);
        expect(result.mutated).toBe(true);
        const mutatedLines = result.mutatedCode.split('\n');
        // The guard should be inserted before line 3 with the same indentation
        const guardLine = mutatedLines[2]; // 0-indexed
        expect(guardLine.startsWith('    ')).toBe(true);
    });
});
