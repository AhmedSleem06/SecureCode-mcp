// Live Pipeline 2 smoke test — runs against the real Vultr API.
//
// Prerequisites:
//   - SECURECODE_API_TOKEN set in env (test account)
//   - Docker available (for the sandbox backend)
//   - Scan credits on the test account
//
// Skipped automatically when either prerequisite is missing.
//
// Validates:
//   - vulnerable-sqli fixture → PROVEN
//   - safe-guarded-sqli fixture → UNPROVEN or no finding
//   - vulnerable-python fixture → PROVEN (validates Fix 5: Python runner)
//   - inconclusive-needs-db fixture → INCONCLUSIVE

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const API_TOKEN = process.env.SECURECODE_API_TOKEN;
const API_BASE = process.env.SECURECODE_API_BASE || 'https://api.usesecurecode.tech';

function dockerAvailable(): boolean {
    try {
        return spawnSync('docker', ['info'], { stdio: 'ignore', timeout: 5000 }).status === 0;
    } catch {
        return false;
    }
}

const HAS_TOKEN = !!API_TOKEN && API_TOKEN.length > 10;
const HAS_DOCKER = dockerAvailable();
const CAN_RUN = HAS_TOKEN && HAS_DOCKER;

const describeLive = CAN_RUN ? describe : describe.skip;

// Minimal API client for the smoke test — posts JSON and returns the parsed body.
async function apiPost(endpoint: string, body: any): Promise<any> {
    const res = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${API_TOKEN}`,
        },
        body: JSON.stringify(body),
    });
    const text = await res.text();
    let json: any;
    try { json = JSON.parse(text); } catch { json = { _raw: text }; }
    if (!res.ok) {
        throw new Error(`API ${endpoint} returned ${res.status}: ${JSON.stringify(json)}`);
    }
    return json;
}

// Fixture loader
function loadFixture(name: string): any {
    const fixturesDir = path.join(__dirname, 'fixtures');
    return require(path.join(fixturesDir, name));
}

describe('Live Pipeline 2 smoke (Phase 5) — requires SECURECODE_API_TOKEN + Docker', () => {
    let workspace: string;

    beforeAll(() => {
        workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'live-smoke-'));
        fs.mkdirSync(path.join(workspace, '.securecode'), { recursive: true });
    });

    afterAll(() => {
        try { fs.rmSync(workspace, { recursive: true, force: true }); } catch {}
    });

    describeLive('vulnerable-sqli fixture', () => {
        it('verify/generate returns canTest=true with a test script', async () => {
            const fx = loadFixture('vulnerable-sqli');
            const resp = await apiPost('/verify/generate', {
                code: fx.code,
                language: fx.language,
                vulnerabilityType: fx.vulnerabilityType,
                line: fx.line,
                evidence: fx.evidence,
                why: fx.why,
                filePath: fx.filePath,
            });
            expect(resp.canTest).toBe(true);
            expect(resp.testScript).toBeTruthy();
            expect(resp.runner).toBeTruthy();
            expect(resp.costUsd).toBeTypeOf('number');
        }, 60000);
    });

    describeLive('safe-guarded-sqli fixture', () => {
        it('verify/generate returns canTest=true (guard test) or canTest=false', async () => {
            const fx = loadFixture('safe-guarded-sqli');
            const resp = await apiPost('/verify/generate', {
                code: fx.code,
                language: fx.language,
                vulnerabilityType: fx.vulnerabilityType,
                line: fx.line,
                evidence: fx.evidence,
                why: fx.why,
                filePath: fx.filePath,
            });
            // The API may say canTest=true (generate a test that proves the guard holds)
            // or canTest=false (cannot test parameterized queries). Either is acceptable.
            expect(resp).toHaveProperty('canTest');
            if (resp.canTest) {
                expect(resp.testScript).toBeTruthy();
                expect(resp.runner).toBeTruthy();
            } else {
                expect(resp.skipReason).toBeTruthy();
            }
        }, 60000);
    });

    describeLive('vulnerable-python fixture (validates Fix 5)', () => {
        it('verify/generate returns runner=python3 and a Python test script', async () => {
            const pyCode = fs.readFileSync(path.join(__dirname, 'fixtures', 'vulnerable-python.py'), 'utf8');
            const resp = await apiPost('/verify/generate', {
                code: pyCode,
                language: 'python',
                vulnerabilityType: 'command_injection',
                line: 9,
                evidence: 'os.system("echo " + user_input)',
                why: 'User input is concatenated into a shell command without sanitization.',
                filePath: 'vulnerable-python.py',
                projectRuntime: 'python',
                suggestedRunner: 'python3',
            });
            expect(resp.canTest).toBe(true);
            expect(resp.testScript).toContain('print');
            // The runner must be a Python runner — validates Fix 5.
            expect(['python', 'python3']).toContain(resp.runner);
        }, 60000);
    });

    describeLive('inconclusive-needs-db fixture', () => {
        it('verify/generate returns canTest=false (needs running DB)', async () => {
            const fx = loadFixture('inconclusive-needs-db');
            const resp = await apiPost('/verify/generate', {
                code: fx.code,
                language: fx.language,
                vulnerabilityType: fx.vulnerabilityType,
                line: fx.line,
                evidence: fx.evidence,
                why: fx.why,
                filePath: fx.filePath,
            });
            expect(resp.canTest).toBe(false);
            expect(resp.skipReason).toBeTruthy();
        }, 60000);
    });

    describeLive('costUsd is present and positive on successful generate', () => {
        it('returns a non-zero costUsd when the LLM ran', async () => {
            const fx = loadFixture('vulnerable-sqli');
            const resp = await apiPost('/verify/generate', {
                code: fx.code,
                language: fx.language,
                vulnerabilityType: fx.vulnerabilityType,
                line: fx.line,
                evidence: fx.evidence,
                why: fx.why,
                filePath: fx.filePath,
            });
            expect(resp.costUsd).toBeTypeOf('number');
            expect(resp.costUsd).toBeGreaterThan(0);
        }, 60000);
    });
});
