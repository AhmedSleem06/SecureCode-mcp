import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { saveProofArtifact, type ProofArtifact } from '../src/attack/proofArtifacts';

function makeArtifact(overrides: Partial<ProofArtifact> = {}): ProofArtifact {
    return {
        proofId: 'proof-1',
        createdAt: '2026-11-13T00:00:00.000Z',
        finding: { file: 'src/app.ts', line: 42, type: 'sql_injection', severity: 'high' },
        rounds: [
            { round: 1, testScript: 'console.log("PASS")', setupScript: '', runner: 'node', verdict: 'pass', output: 'PASS: exploit worked' },
        ],
        proofGate: { failedGates: [], warnings: ['w1'] },
        mutation: { description: 'parameterize query', mutatedVerdict: 'fail', reason: 'discriminating' },
        finalVerdict: 'PROVEN',
        finalReason: 'exploit succeeded',
        ...overrides,
    };
}

describe('saveProofArtifact', () => {
    let root: string;

    beforeEach(() => {
        root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-proof-'));
    });

    afterEach(() => {
        fs.rmSync(root, { recursive: true, force: true });
    });

    it('writes .securecode/proofs/<proofId>.json and returns a forward-slash relative path', () => {
        const rel = saveProofArtifact(root, makeArtifact());
        expect(rel).toBe('.securecode/proofs/proof-1.json');
        const saved = JSON.parse(fs.readFileSync(path.join(root, rel!), 'utf8'));
        expect(Object.keys(saved)).toEqual(['proofId', 'createdAt', 'finding', 'rounds', 'proofGate', 'mutation', 'finalVerdict', 'finalReason']);
        expect(saved.finding).toEqual({ file: 'src/app.ts', line: 42, type: 'sql_injection', severity: 'high' });
        expect(saved.rounds[0].testScript).toBe('console.log("PASS")');
        expect(saved.mutation.description).toBe('parameterize query');
        expect(saved.proofGate.warnings).toEqual(['w1']);
    });

    it('redacts secrets in scripts, outputs and reasons', () => {
        const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlc2lnbmF0dXJl';
        const apiKey = 'a'.repeat(32);
        const rel = saveProofArtifact(root, makeArtifact({
            rounds: [{
                round: 1,
                testScript: `const token = "${jwt}"; fetch(u, { headers: { Authorization: "Bearer abc.def-123" } });`,
                setupScript: `KEY=${apiKey}`,
                runner: 'node',
                verdict: 'pass',
                output: 'sent mail to admin@example.com',
            }],
            finalReason: `leaked ${apiKey}`,
        }));
        const raw = fs.readFileSync(path.join(root, rel!), 'utf8');
        expect(raw).not.toContain(jwt);
        expect(raw).not.toContain(apiKey);
        expect(raw).not.toContain('admin@example.com');
        expect(raw).not.toContain('abc.def-123');
        expect(raw).toContain('[JWT_REDACTED]');
        expect(raw).toContain('[EMAIL_REDACTED]');
    });

    it('caps each string field at 8,000 chars with a truncation suffix', () => {
        const big = 'x '.repeat(10_000);
        const rel = saveProofArtifact(root, makeArtifact({
            rounds: [{ round: 1, testScript: big, setupScript: '', runner: 'node', verdict: 'pass', output: big }],
        }));
        const saved = JSON.parse(fs.readFileSync(path.join(root, rel!), 'utf8'));
        expect(saved.rounds[0].testScript.length).toBe(8_000 + '…[truncated]'.length);
        expect(saved.rounds[0].testScript.endsWith('…[truncated]')).toBe(true);
        expect(saved.rounds[0].output.endsWith('…[truncated]')).toBe(true);
    });

    it('keeps only the newest 200 artifacts', () => {
        const dir = path.join(root, '.securecode', 'proofs');
        fs.mkdirSync(dir, { recursive: true });
        const base = Date.now() / 1000 - 10_000;
        for (let i = 0; i < 205; i++) {
            const f = path.join(dir, `old-${String(i).padStart(3, '0')}.json`);
            fs.writeFileSync(f, '{}');
            fs.utimesSync(f, base + i, base + i);
        }
        const rel = saveProofArtifact(root, makeArtifact({ proofId: 'newest' }));
        expect(rel).toBe('.securecode/proofs/newest.json');
        const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
        expect(files.length).toBe(200);
        expect(files).toContain('newest.json');
        expect(files).toContain('old-204.json');
        for (let i = 0; i <= 5; i++) expect(files).not.toContain(`old-${String(i).padStart(3, '0')}.json`);
        expect(files).toContain('old-006.json');
    });

    it('sanitizes the proofId into a safe file name', () => {
        const rel = saveProofArtifact(root, makeArtifact({ proofId: '../../evil id' }));
        expect(rel).toBe('.securecode/proofs/______evil_id.json');
        expect(fs.existsSync(path.join(root, '.securecode', 'proofs', '______evil_id.json'))).toBe(true);
    });

    it('returns null instead of throwing when the directory cannot be created', () => {
        fs.writeFileSync(path.join(root, '.securecode'), 'not a directory');
        expect(() => saveProofArtifact(root, makeArtifact())).not.toThrow();
        expect(saveProofArtifact(root, makeArtifact())).toBeNull();
    });
});

describe('proof artifact folder is kept out of git', () => {
    it('writes a .gitignore that ignores everything in the proofs folder', () => {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-proof-ignore-'));
        const rel = saveProofArtifact(root, makeArtifact({ proofId: 'p1' }));
        expect(rel).toBeTruthy();
        const ignore = path.join(root, path.dirname(rel));
        expect(fs.readFileSync(path.join(ignore, '.gitignore'), 'utf8')).toBe('*\n');
    });
});
