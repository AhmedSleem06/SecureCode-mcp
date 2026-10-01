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
    listCachedCompletedScans,
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
            terminationReason: 'agent_finish',
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
            terminationReason: 'agent_finish',
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
            terminationReason: 'agent_finish',
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

    it('persists terminationReason in the cache entry', () => {
        const code = 'const x = 1;';
        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [],
            status: 'completed',
            terminationReason: 'agent_finish',
            summary: 'ok',
            stepsUsed: 3,
            costSpentUsd: 0.01,
        });

        const cached = getCachedScan(workspaceRoot, 'src/foo.ts', code);
        expect(cached).not.toBeNull();
        expect(cached!.terminationReason).toBe('agent_finish');
    });

    it('keeps completed status when terminationReason is agent_finish', () => {
        const code = 'const x = 1;';
        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [],
            status: 'completed',
            terminationReason: 'agent_finish',
            stepsUsed: 1, costSpentUsd: 0,
        });

        const cached = getCachedScan(workspaceRoot, 'src/foo.ts', code);
        expect(cached).not.toBeNull();
        expect(cached!.status).toBe('completed');
    });

    it('returns null for legacy completed entries without terminationReason', () => {
        const code = 'const x = 1;';
        // Simulate a legacy entry: write with completed status but no
        // terminationReason — downgraded to incomplete, then rejected.
        const dir = path.join(workspaceRoot, '.securecode');
        const cacheFile = path.join(dir, 'scan-cache.json');
        const fileHash = crypto.createHash('sha256').update(code).digest('hex').slice(0, 16);
        const legacyEntry = {
            fileHash,
            version: AGENT_SCAN_CACHE_VERSION,
            timestamp: Date.now(),
            findings: [],
            status: 'completed',
            summary: 'old scan',
            stepsUsed: 10,
            costSpentUsd: 0.05,
            filePath: 'src/foo.ts',
            memoryHash: '',
        };
        const key = 'src/foo.ts:' + fileHash;
        fs.writeFileSync(cacheFile, JSON.stringify({
            version: AGENT_SCAN_CACHE_VERSION,
            entries: { [key]: legacyEntry },
        }, null, 2));

        const cached = getCachedScan(workspaceRoot, 'src/foo.ts', code);
        expect(cached).toBeNull();
    });

    it('returns null for completed entries with non-agent_finish terminationReason', () => {
        const code = 'const x = 1;';
        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [],
            status: 'completed',
            terminationReason: 'blocked_read_recovery',
            stepsUsed: 1, costSpentUsd: 0,
        });

        const cached = getCachedScan(workspaceRoot, 'src/foo.ts', code);
        expect(cached).toBeNull();
    });

    it('returns null for incomplete status entries', () => {
        const code = 'const x = 1;';
        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [],
            status: 'incomplete',
            terminationReason: 'wall_clock',
            stepsUsed: 1, costSpentUsd: 0,
        });

        const cached = getCachedScan(workspaceRoot, 'src/foo.ts', code);
        expect(cached).toBeNull();
    });

    it('returns null for legacy capped status', () => {
        const code = 'const x = 1;';
        const dir = path.join(workspaceRoot, '.securecode');
        const cacheFile = path.join(dir, 'scan-cache.json');
        const fileHash = crypto.createHash('sha256').update(code).digest('hex').slice(0, 16);
        const key = 'src/foo.ts:' + fileHash;
        fs.writeFileSync(cacheFile, JSON.stringify({
            version: AGENT_SCAN_CACHE_VERSION,
            entries: { [key]: {
                fileHash, version: AGENT_SCAN_CACHE_VERSION, timestamp: Date.now(),
                findings: [], status: 'capped', stepsUsed: 10, costSpentUsd: 0.05,
                filePath: 'src/foo.ts',
            }},
        }, null, 2));

        const cached = getCachedScan(workspaceRoot, 'src/foo.ts', code);
        expect(cached).toBeNull();
    });

    it('returns null for legacy spawn_failed status', () => {
        const code = 'const x = 1;';
        const dir = path.join(workspaceRoot, '.securecode');
        const cacheFile = path.join(dir, 'scan-cache.json');
        const fileHash = crypto.createHash('sha256').update(code).digest('hex').slice(0, 16);
        const key = 'src/foo.ts:' + fileHash;
        fs.writeFileSync(cacheFile, JSON.stringify({
            version: AGENT_SCAN_CACHE_VERSION,
            entries: { [key]: {
                fileHash, version: AGENT_SCAN_CACHE_VERSION, timestamp: Date.now(),
                findings: [], status: 'spawn_failed', stepsUsed: 0, costSpentUsd: 0,
                filePath: 'src/foo.ts',
            }},
        }, null, 2));

        const cached = getCachedScan(workspaceRoot, 'src/foo.ts', code);
        expect(cached).toBeNull();
    });

    it('returns null for legacy blocked_recovery status', () => {
        const code = 'const x = 1;';
        const dir = path.join(workspaceRoot, '.securecode');
        const cacheFile = path.join(dir, 'scan-cache.json');
        const fileHash = crypto.createHash('sha256').update(code).digest('hex').slice(0, 16);
        const key = 'src/foo.ts:' + fileHash;
        fs.writeFileSync(cacheFile, JSON.stringify({
            version: AGENT_SCAN_CACHE_VERSION,
            entries: { [key]: {
                fileHash, version: AGENT_SCAN_CACHE_VERSION, timestamp: Date.now(),
                findings: [], status: 'blocked_recovery', stepsUsed: 5, costSpentUsd: 0.03,
                filePath: 'src/foo.ts',
            }},
        }, null, 2));

        const cached = getCachedScan(workspaceRoot, 'src/foo.ts', code);
        expect(cached).toBeNull();
    });
});

describe('non-completed results are never served', () => {
    let workspaceRoot: string;

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'scancache-'));
        fs.mkdirSync(path.join(workspaceRoot, '.securecode'), { recursive: true });
    });

    afterEach(() => {
        try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
    });

    it('returns null for status incomplete', () => {
        const code = 'const x = 1;';
        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [],
            status: 'incomplete',
            terminationReason: 'wall_clock',
            stepsUsed: 1, costSpentUsd: 0,
        });

        expect(getCachedScan(workspaceRoot, 'src/foo.ts', code)).toBeNull();
    });

    it('returns null for status failed', () => {
        const code = 'const x = 1;';
        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [],
            status: 'failed',
            stepsUsed: 1, costSpentUsd: 0,
        });

        expect(getCachedScan(workspaceRoot, 'src/foo.ts', code)).toBeNull();
    });

    it('returns null for status cancelled', () => {
        const code = 'const x = 1;';
        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [],
            status: 'cancelled',
            stepsUsed: 1, costSpentUsd: 0,
        });

        expect(getCachedScan(workspaceRoot, 'src/foo.ts', code)).toBeNull();
    });

    it('returns null for legacy blocked_recovery status (downgraded to incomplete, then guarded)', () => {
        const code = 'const x = 1;';
        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [],
            status: 'blocked_recovery',
            stepsUsed: 5, costSpentUsd: 0.03,
        });

        expect(getCachedScan(workspaceRoot, 'src/foo.ts', code)).toBeNull();
    });

    it('serves completed entries with terminationReason agent_finish (control case)', () => {
        const code = 'const x = 1;';
        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [{ type: 'sql_injection', line: 5, evidence: 'exec(input)' }],
            status: 'completed',
            terminationReason: 'agent_finish',
            stepsUsed: 3, costSpentUsd: 0.01,
        });

        const cached = getCachedScan(workspaceRoot, 'src/foo.ts', code);
        expect(cached).not.toBeNull();
        expect(cached!.status).toBe('completed');
        expect(cached!.terminationReason).toBe('agent_finish');
    });

    it('returns null for completed entries with legacy budget_exhausted terminationReason (downgraded, then guarded)', () => {
        const code = 'const x = 1;';
        writeCachedScan(workspaceRoot, 'src/foo.ts', code, {
            findings: [],
            status: 'completed',
            terminationReason: 'budget_exhausted',
            stepsUsed: 50, costSpentUsd: 0.5,
        });

        expect(getCachedScan(workspaceRoot, 'src/foo.ts', code)).toBeNull();
    });
});

describe('listCachedCompletedScans', () => {
    let workspaceRoot: string;
    let cacheFile: string;

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'scancache-list-'));
        const dir = path.join(workspaceRoot, '.securecode');
        fs.mkdirSync(dir, { recursive: true });
        cacheFile = path.join(dir, 'scan-cache.json');
    });

    afterEach(() => {
        try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
    });

    function writeRawCache(entries: Record<string, any>) {
        fs.writeFileSync(cacheFile, JSON.stringify({
            version: AGENT_SCAN_CACHE_VERSION,
            entries,
        }, null, 2));
    }

    it('returns [] when no cache file exists', () => {
        expect(listCachedCompletedScans(workspaceRoot)).toEqual([]);
    });

    it('returns [] for an empty cache', () => {
        writeRawCache({});
        expect(listCachedCompletedScans(workspaceRoot)).toEqual([]);
    });

    it('lists completed agent_finish entries with parsed paths and finding counts, sorted desc', () => {
        const now = Date.now();
        writeRawCache({
            'src/old.ts:aaaa1111': {
                fileHash: 'aaaa1111', version: AGENT_SCAN_CACHE_VERSION, timestamp: now - 5000,
                findings: [{ type: 'xss' }, { type: 'sqli' }], status: 'completed',
                terminationReason: 'agent_finish', stepsUsed: 3, costSpentUsd: 0, filePath: 'src/old.ts',
            },
            'src/new.ts:bbbb2222': {
                fileHash: 'bbbb2222', version: AGENT_SCAN_CACHE_VERSION, timestamp: now,
                findings: [{ type: 'ssrf' }], status: 'completed',
                terminationReason: 'agent_finish', stepsUsed: 2, costSpentUsd: 0, filePath: 'src/new.ts',
            },
            'C:/proj/src/abs.ts:cccc3333': {
                fileHash: 'cccc3333', version: AGENT_SCAN_CACHE_VERSION, timestamp: now - 1000,
                findings: [], status: 'completed',
                terminationReason: 'agent_finish', stepsUsed: 1, costSpentUsd: 0, filePath: 'C:/proj/src/abs.ts',
            },
        });

        const list = listCachedCompletedScans(workspaceRoot);
        expect(list).toHaveLength(3);
        // Sorted by timestamp desc — newest first.
        expect(list[0].filePath).toBe('src/new.ts');
        expect(list[0].findings).toBe(1);
        expect(list[1].filePath).toBe('C:/proj/src/abs.ts');
        expect(list[1].findings).toBe(0);
        expect(list[2].filePath).toBe('src/old.ts');
        expect(list[2].findings).toBe(2);
        // scannedAt is an ISO string of the entry timestamp.
        expect(list[0].scannedAt).toBe(new Date(now).toISOString());
    });

    it('excludes incomplete and non-agent_finish entries', () => {
        const now = Date.now();
        writeRawCache({
            'src/inc.ts:aaaa1111': {
                fileHash: 'aaaa1111', version: AGENT_SCAN_CACHE_VERSION, timestamp: now,
                findings: [], status: 'incomplete', terminationReason: 'wall_clock',
                stepsUsed: 1, costSpentUsd: 0, filePath: 'src/inc.ts',
            },
            'src/blocked.ts:bbbb2222': {
                fileHash: 'bbbb2222', version: AGENT_SCAN_CACHE_VERSION, timestamp: now,
                findings: [], status: 'completed', terminationReason: 'blocked_read_recovery',
                stepsUsed: 1, costSpentUsd: 0, filePath: 'src/blocked.ts',
            },
            'src/legacy.ts:cccc3333': {
                fileHash: 'cccc3333', version: AGENT_SCAN_CACHE_VERSION, timestamp: now,
                findings: [], status: 'completed',
                stepsUsed: 1, costSpentUsd: 0, filePath: 'src/legacy.ts',
            },
        });

        expect(listCachedCompletedScans(workspaceRoot)).toEqual([]);
    });

    it('excludes version-mismatched entries', () => {
        const now = Date.now();
        writeRawCache({
            'src/stale.ts:aaaa1111': {
                fileHash: 'aaaa1111', version: AGENT_SCAN_CACHE_VERSION - 1, timestamp: now,
                findings: [{ type: 'xss' }], status: 'completed',
                terminationReason: 'agent_finish', stepsUsed: 3, costSpentUsd: 0, filePath: 'src/stale.ts',
            },
        });

        expect(listCachedCompletedScans(workspaceRoot)).toEqual([]);
    });

    it('excludes TTL-expired entries', () => {
        writeRawCache({
            'src/old.ts:aaaa1111': {
                fileHash: 'aaaa1111', version: AGENT_SCAN_CACHE_VERSION,
                timestamp: Date.now() - 8 * 24 * 60 * 60 * 1000,
                findings: [], status: 'completed',
                terminationReason: 'agent_finish', stepsUsed: 3, costSpentUsd: 0, filePath: 'src/old.ts',
            },
        });

        expect(listCachedCompletedScans(workspaceRoot)).toEqual([]);
    });

    it('caps the listing at 20 entries', () => {
        const now = Date.now();
        const entries: Record<string, any> = {};
        for (let i = 0; i < 25; i++) {
            const key = `src/f${i}.ts:hash${String(i).padStart(4, '0')}`;
            entries[key] = {
                fileHash: `hash${String(i).padStart(4, '0')}`, version: AGENT_SCAN_CACHE_VERSION,
                timestamp: now - i * 1000,
                findings: [], status: 'completed', terminationReason: 'agent_finish',
                stepsUsed: 1, costSpentUsd: 0, filePath: `src/f${i}.ts`,
            };
        }
        writeRawCache(entries);

        const list = listCachedCompletedScans(workspaceRoot);
        expect(list).toHaveLength(20);
        // Newest 20 — f0 (newest) through f19; f20..f24 dropped.
        expect(list[0].filePath).toBe('src/f0.ts');
        expect(list[19].filePath).toBe('src/f19.ts');
        expect(list.some(s => s.filePath === 'src/f24.ts')).toBe(false);
    });

    it('lists entries written by writeCachedScan (key-format integration)', () => {
        writeCachedScan(workspaceRoot, 'src/real.ts', 'const real = 1;', {
            findings: [{ type: 'sql_injection' }],
            status: 'completed',
            terminationReason: 'agent_finish',
            stepsUsed: 4,
            costSpentUsd: 0.02,
        });

        const list = listCachedCompletedScans(workspaceRoot);
        expect(list).toHaveLength(1);
        expect(list[0].filePath).toBe('src/real.ts');
        expect(list[0].findings).toBe(1);
        expect(new Date(list[0].scannedAt).getTime()).toBeGreaterThan(0);
    });
});
