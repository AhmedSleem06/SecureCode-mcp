import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import {
    getCachedScan,
    writeCachedScan,
    computeMemoryFingerprint,
    filterCachedFindingsAgainstMemory,
    AGENT_SCAN_CACHE_VERSION,
} from '../src/project-map/scanCache';

function hashEvidence(evidence: string): string {
    return crypto.createHash('sha256').update(evidence).digest('hex').slice(0, 16);
}

describe('scanCache — memory coherence', () => {
    let workspaceRoot: string;

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'scancache-'));
        fs.mkdirSync(path.join(workspaceRoot, '.securecode'), { recursive: true });
    });

    afterEach(() => {
        try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
    });

    it('writes and reads a cache entry with memoryHash', () => {
        const code = 'const x = 1;';
        const fps = [{ findingType: 'sql_injection', evidenceHash: hashEvidence('exec(input)') }];
        const memHash = computeMemoryFingerprint(fps);

        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [{ type: 'sql_injection', line: 5, evidence: 'exec(input)' }],
            status: 'completed',
            summary: 'ok',
            stepsUsed: 3,
            costSpentUsd: 0.01,
        }, memHash);

        const cached = getCachedScan(workspaceRoot, 'src/foo.ts', code);
        expect(cached).not.toBeNull();
        expect(cached!.memoryHash).toBe(memHash);
        expect(cached!.version).toBe(AGENT_SCAN_CACHE_VERSION);
    });

    it('returns cached findings unchanged when memory fingerprint matches', () => {
        // Memory state at write time: 1 dismissed SQLi.
        // At read time: same 1 dismissed SQLi → fingerprint matches → return as-is.
        // The cached findings may still contain the dismissed finding because
        // the agent's scan with that memory state already produced them (the
        // memory is advisory to the agent, not a hard filter on its output).
        // The fingerprint-match path trusts the cached result.
        const code = 'const x = 1;';
        const fps = [{ findingType: 'sql_injection', evidenceHash: hashEvidence('exec(input)') }];
        const memHash = computeMemoryFingerprint(fps);

        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [{ type: 'sql_injection', line: 5, evidence: 'exec(input)' }],
            status: 'completed',
            stepsUsed: 1, costSpentUsd: 0,
        }, memHash);

        const cached = getCachedScan(workspaceRoot, 'src/foo.ts', code)!;
        // Caller pattern: when fingerprints match, return cached.findings as-is.
        const filtered = (cached.memoryHash === memHash)
            ? cached.findings
            : filterCachedFindingsAgainstMemory(cached.findings, fps);
        expect(filtered.length).toBe(1);
    });

    it('drops cached findings that match a newly-dismissed false positive', () => {
        // Cache was written when nothing was dismissed.
        const code = 'const x = 1;';
        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [
                { type: 'sql_injection', line: 5, evidence: 'exec(input)' },
                { type: 'xss', line: 10, evidence: 'innerHTML = userInput' },
            ],
            status: 'completed',
            stepsUsed: 1, costSpentUsd: 0,
        }, '');  // empty fingerprint — no FPs at write time

        // Now the user dismisses the SQLi finding.
        const newFps = [{ findingType: 'sql_injection', evidenceHash: hashEvidence('exec(input)') }];
        const cached = getCachedScan(workspaceRoot, 'src/foo.ts', code)!;
        // cached.memoryHash ('') differs from current fingerprint, so filter.
        const filtered = filterCachedFindingsAgainstMemory(cached.findings, newFps);
        expect(filtered.length).toBe(1);
        expect(filtered[0].type).toBe('xss');
    });

    it('computeMemoryFingerprint is deterministic and order-independent', () => {
        const fpsA = [
            { findingType: 'xss', evidenceHash: 'aaa' },
            { findingType: 'sqli', evidenceHash: 'bbb' },
        ];
        const fpsB = [
            { findingType: 'sqli', evidenceHash: 'bbb' },
            { findingType: 'xss', evidenceHash: 'aaa' },
        ];
        expect(computeMemoryFingerprint(fpsA)).toBe(computeMemoryFingerprint(fpsB));
    });

    it('computeMemoryFingerprint returns empty string for no false positives', () => {
        expect(computeMemoryFingerprint([])).toBe('');
    });
});
