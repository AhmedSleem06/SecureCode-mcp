import { describe, it, expect } from 'vitest';
import { sanitizeFindings, isCoherentText, compactTranscript, compactTranscriptAggressive, estimateTranscriptSize } from '../src/attack/agentScanLoop';
import { InvestigationState } from '../src/attack/investigationState';

interface QualityFixture {
    name: string;
    input: any[];
    expected: {
        count: number;
        severities: string[];
        minConfidence: number;
        maxConfidence: number;
        allHaveLine: boolean;
        allHaveType: boolean;
        allHaveWhy: boolean;
        noControlChars: boolean;
        noDuplicates: boolean;
    };
}

const FIXTURES: QualityFixture[] = [
    {
        name: 'valid-findings',
        input: [
            { line: 10, type: 'sql-injection', severity: 'high', confidence: 0.85, why: 'User input flows into SQL query without parameterization', evidence: 'db.query(req.body.input)' },
            { line: 25, type: 'xss', severity: 'medium', confidence: 0.6, why: 'Unescaped output in template', evidence: 'res.send(userInput)' },
        ],
        expected: {
            count: 2, severities: ['high', 'medium'], minConfidence: 0.6, maxConfidence: 0.85,
            allHaveLine: true, allHaveType: true, allHaveWhy: true, noControlChars: true, noDuplicates: true,
        },
    },
    {
        name: 'missing-fields',
        input: [{ why: 'some explanation here' }],
        expected: {
            count: 1, severities: ['low'], minConfidence: 0.3, maxConfidence: 0.3,
            allHaveLine: true, allHaveType: true, allHaveWhy: true, noControlChars: true, noDuplicates: true,
        },
    },
    {
        name: 'incoherent-why-downgrade',
        input: [{ line: 1, type: 'rce', severity: 'critical', confidence: 0.95, why: '   ', evidence: 'x' }],
        expected: {
            count: 1, severities: ['medium'], minConfidence: 0, maxConfidence: 0.3,
            allHaveLine: true, allHaveType: true, allHaveWhy: true, noControlChars: true, noDuplicates: true,
        },
    },
    {
        name: 'invalid-severity-fixed',
        input: [{ line: 1, type: 'xss', severity: 'extreme', confidence: 0.5, why: 'valid explanation text', evidence: 'x' }],
        expected: {
            count: 1, severities: ['low'], minConfidence: 0.5, maxConfidence: 0.5,
            allHaveLine: true, allHaveType: true, allHaveWhy: true, noControlChars: true, noDuplicates: true,
        },
    },
    {
        name: 'confidence-clamped',
        input: [
            { line: 1, type: 'a', severity: 'low', confidence: 5, why: 'valid explanation here', evidence: 'x' },
            { line: 2, type: 'b', severity: 'low', confidence: -1, why: 'another valid one', evidence: 'y' },
        ],
        expected: {
            count: 2, severities: ['low', 'low'], minConfidence: 0, maxConfidence: 1,
            allHaveLine: true, allHaveType: true, allHaveWhy: true, noControlChars: true, noDuplicates: true,
        },
    },
    {
        name: 'duplicates-removed',
        input: [
            { line: 42, type: 'xss', severity: 'high', confidence: 0.8, why: 'first valid explanation', evidence: 'a' },
            { line: 42, type: 'xss', severity: 'medium', confidence: 0.5, why: 'second valid explanation', evidence: 'b' },
        ],
        expected: {
            count: 1, severities: ['high'], minConfidence: 0.8, maxConfidence: 0.8,
            allHaveLine: true, allHaveType: true, allHaveWhy: true, noControlChars: true, noDuplicates: true,
        },
    },
    {
        name: 'control-chars-stripped',
        input: [{ line: 1, type: 'xss', severity: 'low', confidence: 0.5, why: 'valid \x00 explanation here', evidence: 'code \x01 here' }],
        expected: {
            count: 1, severities: ['low'], minConfidence: 0.5, maxConfidence: 0.5,
            allHaveLine: true, allHaveType: true, allHaveWhy: true, noControlChars: true, noDuplicates: true,
        },
    },
    {
        name: 'empty-input',
        input: [],
        expected: {
            count: 0, severities: [], minConfidence: 1, maxConfidence: 0,
            allHaveLine: true, allHaveType: true, allHaveWhy: true, noControlChars: true, noDuplicates: true,
        },
    },
    {
        name: 'null-input',
        input: null as any,
        expected: {
            count: 0, severities: [], minConfidence: 1, maxConfidence: 0,
            allHaveLine: true, allHaveType: true, allHaveWhy: true, noControlChars: true, noDuplicates: true,
        },
    },
];

function runScorecard(fixture: QualityFixture): { passed: boolean; checks: { name: string; passed: boolean; actual: any; expected: any }[] } {
    const result = sanitizeFindings(fixture.input);
    const checks: { name: string; passed: boolean; actual: any; expected: any }[] = [];

    checks.push({ name: 'count', passed: result.length === fixture.expected.count, actual: result.length, expected: fixture.expected.count });
    checks.push({ name: 'severities', passed: JSON.stringify(result.map((f: any) => f.severity)) === JSON.stringify(fixture.expected.severities), actual: result.map((f: any) => f.severity), expected: fixture.expected.severities });

    if (result.length > 0) {
        const confs = result.map((f: any) => f.confidence);
        const minConf = Math.min(...confs);
        const maxConf = Math.max(...confs);
        checks.push({ name: 'minConfidence', passed: minConf >= fixture.expected.minConfidence, actual: minConf, expected: `>= ${fixture.expected.minConfidence}` });
        checks.push({ name: 'maxConfidence', passed: maxConf <= fixture.expected.maxConfidence, actual: maxConf, expected: `<= ${fixture.expected.maxConfidence}` });
        checks.push({ name: 'allHaveLine', passed: result.every((f: any) => typeof f.line === 'number'), actual: result.every((f: any) => typeof f.line === 'number'), expected: fixture.expected.allHaveLine });
        checks.push({ name: 'allHaveType', passed: result.every((f: any) => typeof f.type === 'string' && f.type.length > 0), actual: result.every((f: any) => typeof f.type === 'string' && f.type.length > 0), expected: fixture.expected.allHaveType });
        checks.push({ name: 'allHaveWhy', passed: result.every((f: any) => typeof f.why === 'string' && f.why.length > 0), actual: result.every((f: any) => typeof f.why === 'string' && f.why.length > 0), expected: fixture.expected.allHaveWhy });
        checks.push({ name: 'noControlChars', passed: result.every((f: any) => !/[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFD]/.test(f.why || '') && !/[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFD]/.test(f.evidence || '')), actual: 'checked', expected: fixture.expected.noControlChars });
        const dedupKeys = result.map((f: any) => `${f.type}:${f.line}`);
        checks.push({ name: 'noDuplicates', passed: new Set(dedupKeys).size === dedupKeys.length, actual: dedupKeys.length, expected: new Set(dedupKeys).size });
    }

    return { passed: checks.every(c => c.passed), checks };
}

describe('Quality Regression Harness', () => {
    it('all fixtures pass the scorecard', () => {
        const failures: string[] = [];
        for (const fixture of FIXTURES) {
            const result = runScorecard(fixture);
            if (!result.passed) {
                const failedChecks = result.checks.filter(c => !c.passed).map(c => `${c.name} (got ${JSON.stringify(c.actual)}, expected ${JSON.stringify(c.expected)})`);
                failures.push(`${fixture.name}: ${failedChecks.join(', ')}`);
            }
        }
        expect(failures).toEqual([]);
    });

    it.each(FIXTURES.map(f => [f.name, f] as const))('fixture: %s', (name, fixture) => {
        const result = runScorecard(fixture);
        if (!result.passed) {
            const failedChecks = result.checks.filter(c => !c.passed).map(c => `${c.name}: expected ${JSON.stringify(c.expected)}, got ${JSON.stringify(c.actual)}`);
            throw new Error(`Fixture "${name}" failed:\n  ${failedChecks.join('\n  ')}`);
        }
        expect(result.passed).toBe(true);
    });

    it('coherent text detection is stable', () => {
        expect(isCoherentText('This is a normal security finding explanation')).toBe(true);
        expect(isCoherentText('')).toBe(false);
        expect(isCoherentText('ab')).toBe(false);
        expect(isCoherentText('\x00\x01\x02')).toBe(false);
        expect(isCoherentText('12345678901234567890')).toBe(false);
    });

    it('transcript compaction preserves recent context', () => {
        const steps = Array.from({ length: 30 }, (_, i) => ({
            action: { type: 'read_file', path: `file${i}.ts` },
            observation: 'x'.repeat(10000),
        }));
        const compacted = compactTranscript(steps);
        expect(compacted.length).toBe(30);
        const recentSize = estimateTranscriptSize(compacted.slice(-12));
        const oldSize = estimateTranscriptSize(compacted.slice(0, 18));
        expect(recentSize).toBeGreaterThan(oldSize);
    });

    it('aggressive compaction is more aggressive than normal', () => {
        const steps = Array.from({ length: 30 }, (_, i) => ({
            action: { type: 'read_file', path: `file${i}.ts` },
            observation: 'x'.repeat(10000),
        }));
        const normal = compactTranscript(steps);
        const aggressive = compactTranscriptAggressive(steps);
        expect(estimateTranscriptSize(aggressive)).toBeLessThanOrEqual(estimateTranscriptSize(normal));
    });

    it('investigation state tracks flow verification', () => {
        const state = new InvestigationState('test.ts', 'generic-utility');
        state.recordFlowVerification('test.ts', 'trace_flow_cross_file', 'confirmed', 2, 'taint flow found');
        expect(state.hasClassifiedFlow()).toBe(true);
        const flows = state.getFlowVerifications();
        expect(flows.length).toBe(1);
        expect(flows[0].status).toBe('confirmed');
    });

    it('investigation state prioritizes security-relevant ranges', () => {
        const state = new InvestigationState('test.ts', 'http-route');
        state.recordActualRead('test.ts', 1, 100, 500, false);
        const nextRange = state.getPrioritizedUnreadRange('test.ts');
        expect(nextRange).toBeTruthy();
        if (nextRange) {
            state.recordActualRead('test.ts', nextRange.start, nextRange.end, 500, false);
        }
    });
});
