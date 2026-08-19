// Cross-repo contract parity — ensures the MCP and API agree on the verify
// protocol surface. Runs in the MCP test suite but reads API files from the
// sibling api/ directory in the same workspace.

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const API_ROOT = path.resolve(__dirname, '..', '..', 'api');
const verifyProveSchemaPath = path.join(API_ROOT, 'src', 'prompts', 'schemas', 'verify-prove.json');
const verifyAnalyzeSchemaPath = path.join(API_ROOT, 'src', 'prompts', 'schemas', 'verify-analyze.json');

function loadJson(p: string): any {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
}

describe('Cross-repo contract parity (Suite 5)', () => {
    describe('verify-prove.json runner enum', () => {
        const schema = loadJson(verifyProveSchemaPath);
        const runnerEnum: string[] = schema.properties.runner.enum;

        it('includes node, tsx, bun (original set)', () => {
            expect(runnerEnum).toContain('node');
            expect(runnerEnum).toContain('tsx');
            expect(runnerEnum).toContain('bun');
        });

        it('includes deno (Fix 5)', () => {
            expect(runnerEnum).toContain('deno');
        });

        it('includes python and python3 (Fix 5)', () => {
            expect(runnerEnum).toContain('python');
            expect(runnerEnum).toContain('python3');
        });

        it('runner is nullable (canTest=false responses have runner=null)', () => {
            expect(schema.properties.runner.type).toContain('null');
        });
    });

    describe('verify-analyze.json verdict enum', () => {
        const schema = loadJson(verifyAnalyzeSchemaPath);
        const verdictEnum: string[] = schema.properties.verdict.enum;

        it('includes PROVEN, UNPROVEN, INCONCLUSIVE', () => {
            expect(verdictEnum).toContain('PROVEN');
            expect(verdictEnum).toContain('UNPROVEN');
            expect(verdictEnum).toContain('INCONCLUSIVE');
        });

        it('does not allow extraneous verdicts', () => {
            expect(verdictEnum).toHaveLength(3);
        });

        it('shouldRetry is a boolean', () => {
            expect(schema.properties.shouldRetry.type).toBe('boolean');
        });

        it('reason is a string', () => {
            const reasonType = schema.properties.reason.type;
            const t = Array.isArray(reasonType) ? reasonType : [reasonType];
            expect(t).toContain('string');
        });
    });

    describe('MCP validator accepts the same runners the API schema declares', () => {
        // Re-derive the MCP's accepted set by importing the validator and
        // probing each runner. This catches drift without hardcoding.
        const schema = loadJson(verifyProveSchemaPath);
        const apiRunners = schema.properties.runner.enum.filter((r: string) => r !== null);

        it.each(apiRunners.map((r: string) => ['runner:' + r, r]))('%s is accepted by the MCP validator', async (_label, runner) => {
            const { validateVerifyGenerateResponse } = await import('../src/attack/protocolValidator');
            const result = validateVerifyGenerateResponse({
                canTest: true,
                testScript: 'console.log("PASS: x")',
                runner,
            });
            expect(result.ok).toBe(true);
        });
    });

    describe('MCP validator rejects runners NOT in the API schema', () => {
        const schema = loadJson(verifyProveSchemaPath);
        const apiRunners = new Set(schema.properties.runner.enum.filter((r: string) => r !== null));
        const nonSchemaRunners = ['ruby', 'go', 'rust', 'java', 'csharp', 'php'];

        it.each(nonSchemaRunners.map((r: string) => ['runner:' + r, r]))('%s is rejected by the MCP validator', async (_label, runner) => {
            const { validateVerifyGenerateResponse } = await import('../src/attack/protocolValidator');
            const result = validateVerifyGenerateResponse({
                canTest: true,
                testScript: 'console.log("PASS: x")',
                runner,
            });
            expect(result.ok).toBe(false);
            // Sanity: it's rejected because it's not a known runner, not for
            // some unrelated reason.
            if (!result.ok) expect(result.error).toContain('runner');
            // Double-check the API schema also doesn't allow it.
            expect(apiRunners.has(runner)).toBe(false);
        });
    });

    describe('MCP VerifyAnalyzeResponse verdicts match API verify-analyze.json', () => {
        const schema = loadJson(verifyAnalyzeSchemaPath);
        const apiVerdicts = new Set(schema.properties.verdict.enum);

        it.each(['PROVEN', 'UNPROVEN', 'INCONCLUSIVE'] as const)('%s is in the API schema', (v) => {
            expect(apiVerdicts.has(v)).toBe(true);
        });

        it('the MCP validator rejects verdicts not in the API schema', async () => {
            const { validateVerifyAnalyzeResponse } = await import('../src/attack/protocolValidator');
            const result = validateVerifyAnalyzeResponse({
                verdict: 'MAYBE',
                reason: 'unsure',
                shouldRetry: false,
            });
            expect(result.ok).toBe(false);
        });
    });

    describe('MCP VerifyBudget matches plan constants', () => {
        it('defaultVerifyBudget has the documented caps', async () => {
            const { defaultVerifyBudget } = await import('../src/attack/agentScanProtocol');
            const b = defaultVerifyBudget();
            expect(b.maxFindings).toBe(10);
            expect(b.maxRoundsPerFinding).toBe(8);
            expect(b.maxLlmCalls).toBe(40);
            expect(b.maxWallClockMs).toBe(5 * 60 * 1000);
            expect(b.costCapUsd).toBe(0.50);
        });
    });

    describe('AGENT_SCAN_PROTOCOL_VERSION is 2', () => {
        it('MCP protocol version is 2', async () => {
            const mod = await import('../src/attack/agentScanProtocol');
            expect(mod.AGENT_SCAN_PROTOCOL_VERSION).toBe(2);
        });
    });
});
