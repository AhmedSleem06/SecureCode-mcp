import { describe, it, expect } from 'vitest';
import { testFix } from '../src/project-map/fixTester';

describe('Fix Regression Tester', () => {

    // ── Good fix (SQL injection → parameterized query) ─────────────────────

    it('passes when a SQL injection fix removes the vulnerability', async () => {
        const original = `const id = req.body.id;
db.query("SELECT * FROM users WHERE id = " + id);`;
        const fixed = `const id = parseInt(req.body.id, 10);
db.query("SELECT * FROM users WHERE id = ?", [id]);`;

        const result = await testFix(original, fixed, 'javascript', {
            vulnType: 'sql_injection',
        });
        expect(result.syntaxValid).toBe(true);
        expect(result.fixEffective).toBe(true);
        expect(result.newVulnerabilities).toHaveLength(0);
        expect(result.passes).toBe(true);
    });

    it('passes when an eval fix removes command injection', async () => {
        const original = `const x = eval(userInput);`;
        const fixed = `const x = JSON.parse(userInput);`;

        const result = await testFix(original, fixed, 'javascript', {
            vulnType: 'command_injection',
        });
        expect(result.syntaxValid).toBe(true);
        expect(result.fixEffective).toBe(true);
        expect(result.newVulnerabilities).toHaveLength(0);
    });

    it('passes when an XSS fix uses escapeHtml', async () => {
        const original = `element.innerHTML = req.body.html;`;
        const fixed = `element.textContent = req.body.html;`;

        const result = await testFix(original, fixed, 'javascript', {
            vulnType: 'xss',
        });
        expect(result.syntaxValid).toBe(true);
        expect(result.fixEffective).toBe(true);
    });

    // ── Syntax-invalid fix ─────────────────────────────────────────────────

    it('fails when the fixed code has a syntax error', async () => {
        const original = `const x = eval(userInput);`;
        const fixed = `const x = eval(userInput;`;  // missing closing paren

        const result = await testFix(original, fixed, 'javascript', {
            vulnType: 'command_injection',
        });
        expect(result.syntaxValid).toBe(false);
        expect(result.passes).toBe(false);
        expect(result.fixEffective).toBe(false);
    });

    // ── Incomplete fix (vuln still present) ───────────────────────────────

    it('marks fix as not effective when the vulnerability persists', async () => {
        const original = `const id = req.body.id;
db.query("SELECT * FROM users WHERE id = " + id);`;
        const fixed = `const id = req.body.id;
db.query("SELECT * FROM users WHERE id = " + id);  // still vulnerable`;

        const result = await testFix(original, fixed, 'javascript', {
            vulnType: 'sql_injection',
        });
        expect(result.syntaxValid).toBe(true);
        expect(result.fixEffective).toBe(false);
        expect(result.passes).toBe(false);
    });

    // ── Fix introduces new vulnerability ──────────────────────────────────

    it('detects when a fix introduces a new sink', async () => {
        const original = `const id = req.body.id;
db.query("SELECT * FROM users WHERE id = " + id);`;
        // Fix the SQLi but introduce an eval
        const fixed = `const id = parseInt(req.body.id, 10);
db.query("SELECT * FROM users WHERE id = ?", [id]);
const result = eval(req.body.code);`;

        const result = await testFix(original, fixed, 'javascript', {
            vulnType: 'sql_injection',
        });
        expect(result.syntaxValid).toBe(true);
        expect(result.fixEffective).toBe(true);
        expect(result.newVulnerabilities.length).toBeGreaterThan(0);
        expect(result.newVulnerabilities.some(v => v.includes('command_injection'))).toBe(true);
        expect(result.passes).toBe(false);
    });

    it('detects when a fix introduces a new taint flow', async () => {
        const original = `const id = req.body.id;
db.query("SELECT * FROM users WHERE id = " + id);`;
        // Fix SQLi but introduce XSS
        const fixed = `const id = parseInt(req.body.id, 10);
db.query("SELECT * FROM users WHERE id = ?", [id]);
element.innerHTML = req.body.html;`;

        const result = await testFix(original, fixed, 'javascript', {
            vulnType: 'sql_injection',
        });
        expect(result.newVulnerabilities.length).toBeGreaterThan(0);
        expect(result.newVulnerabilities.some(v => v.includes('xss'))).toBe(true);
        expect(result.passes).toBe(false);
    });

    // ── Function removal regression ───────────────────────────────────────

    it('detects when a fix removes a function', async () => {
        const original = `function helper() { return 1; }
const x = eval(userInput);`;
        const fixed = `const x = JSON.parse(userInput);`;  // helper() removed

        const result = await testFix(original, fixed, 'javascript', {
            vulnType: 'command_injection',
        });
        expect(result.regressions.length).toBeGreaterThan(0);
        expect(result.regressions.some(r => r.includes('helper'))).toBe(true);
    });

    it('does not flag regressions when functions are preserved', async () => {
        const original = `function helper() { return 1; }
const x = eval(userInput);`;
        const fixed = `function helper() { return 1; }
const x = JSON.parse(userInput);`;

        const result = await testFix(original, fixed, 'javascript', {
            vulnType: 'command_injection',
        });
        expect(result.regressions).toHaveLength(0);
    });

    // ── Python fixes ───────────────────────────────────────────────────────

    it('passes when a Python SQL injection fix works', async () => {
        const original = `q = request.GET.get('q')
cursor.execute(q)`;
        const fixed = `q = int(request.GET.get('q'))
cursor.execute("SELECT * FROM users WHERE id = ?", (q,))`;

        const result = await testFix(original, fixed, 'python', {
            vulnType: 'sql_injection',
        });
        expect(result.syntaxValid).toBe(true);
        expect(result.fixEffective).toBe(true);
    });

    // ── Edge cases ─────────────────────────────────────────────────────────

    it('handles identical original and fixed code', async () => {
        const code = `const x = eval(userInput);`;
        const result = await testFix(code, code, 'javascript', {
            vulnType: 'command_injection',
        });
        expect(result.syntaxValid).toBe(true);
        // Vuln still present → not effective
        expect(result.fixEffective).toBe(false);
        expect(result.passes).toBe(false);
    });

    it('handles empty fixed code', async () => {
        const original = `const x = eval(userInput);`;
        const result = await testFix(original, '', 'javascript', {
            vulnType: 'command_injection',
        });
        // Empty code may parse as valid (empty program) or not depending on grammar
        // Either way, the eval is gone → fixEffective = true
        expect(result.fixEffective).toBe(true);
    });

    it('returns all test results with name and passed fields', async () => {
        const original = `const x = eval(userInput);`;
        const fixed = `const x = JSON.parse(userInput);`;
        const result = await testFix(original, fixed, 'javascript', {
            vulnType: 'command_injection',
        });
        expect(result.tests.length).toBeGreaterThan(0);
        for (const t of result.tests) {
            expect(t).toHaveProperty('name');
            expect(t).toHaveProperty('passed');
        }
    });

    it('works without specifying vulnType', async () => {
        const original = `const id = req.body.id;
db.query("SELECT * FROM users WHERE id = " + id);`;
        const fixed = `const id = parseInt(req.body.id, 10);
db.query("SELECT * FROM users WHERE id = ?", [id]);`;

        const result = await testFix(original, fixed, 'javascript');
        expect(result.syntaxValid).toBe(true);
        expect(result.newVulnerabilities).toHaveLength(0);
        // Without vulnType, fixEffective checks if sinks/taint decreased
        expect(result.fixEffective).toBe(true);
    });
});
