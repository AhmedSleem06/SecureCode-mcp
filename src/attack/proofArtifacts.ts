import * as fs from 'fs';
import * as path from 'path';
import { redactText } from './report';

export interface ProofArtifactRound {
    round: number;
    testScript: string;
    setupScript: string;
    runner: string;
    verdict: string;
    output: string;
}

export interface ProofArtifact {
    proofId: string;
    createdAt: string;
    phase?: 'original' | 'fix';
    finding: { file: string; line: number; type: string; severity: string };
    rounds: ProofArtifactRound[];
    proofGate: { failedGates: string[]; warnings: string[] } | null;
    mutation: { description: string; mutatedVerdict: string; reason: string } | null;
    finalVerdict: string;
    finalReason: string;
}

export const PROOF_ARTIFACT_DIR = path.join('.securecode', 'proofs');
export const PROOF_ARTIFACT_MAX_CHARS = 8_000;
export const PROOF_ARTIFACT_MAX_FILES = 200;
const TRUNCATED_SUFFIX = '…[truncated]';

function clean(value: unknown): string {
    const text = redactText(typeof value === 'string' ? value : value == null ? '' : String(value));
    return text.length > PROOF_ARTIFACT_MAX_CHARS ? text.slice(0, PROOF_ARTIFACT_MAX_CHARS) + TRUNCATED_SUFFIX : text;
}

function sanitizeArtifact(artifact: ProofArtifact): ProofArtifact {
    return {
        proofId: artifact.proofId,
        createdAt: artifact.createdAt,
        finding: {
            file: clean(artifact.finding.file),
            line: artifact.finding.line,
            type: clean(artifact.finding.type),
            severity: clean(artifact.finding.severity),
        },
        rounds: artifact.rounds.map((r) => ({
            round: r.round,
            testScript: clean(r.testScript),
            setupScript: clean(r.setupScript),
            runner: clean(r.runner),
            verdict: clean(r.verdict),
            output: clean(r.output),
        })),
        proofGate: artifact.proofGate
            ? {
                  failedGates: artifact.proofGate.failedGates.map(clean),
                  warnings: artifact.proofGate.warnings.map(clean),
              }
            : null,
        mutation: artifact.mutation
            ? {
                  description: clean(artifact.mutation.description),
                  mutatedVerdict: clean(artifact.mutation.mutatedVerdict),
                  reason: clean(artifact.mutation.reason),
              }
            : null,
        finalVerdict: clean(artifact.finalVerdict),
        finalReason: clean(artifact.finalReason),
        ...(artifact.phase ? { phase: artifact.phase } : {}),
    };
}

function rotate(dir: string, keepFile: string): void {
    const entries = fs.readdirSync(dir)
        .filter((name) => name.endsWith('.json'))
        .map((name) => {
            try {
                return { name, mtimeMs: fs.statSync(path.join(dir, name)).mtimeMs };
            } catch {
                return null;
            }
        })
        .filter((e): e is { name: string; mtimeMs: number } => e !== null);
    if (entries.length <= PROOF_ARTIFACT_MAX_FILES) return;
    entries.sort((a, b) => {
        if (a.name === keepFile) return -1;
        if (b.name === keepFile) return 1;
        return b.mtimeMs - a.mtimeMs;
    });
    for (const entry of entries.slice(PROOF_ARTIFACT_MAX_FILES)) {
        try { fs.unlinkSync(path.join(dir, entry.name)); } catch { /* best effort */ }
    }
}

export function saveProofArtifact(workspaceRoot: string, artifact: ProofArtifact): string | null {
    try {
        const safeId = (artifact.proofId || `${Date.now()}`).replace(/[^A-Za-z0-9_-]/g, '_');
        const dir = path.join(workspaceRoot, PROOF_ARTIFACT_DIR);
        fs.mkdirSync(dir, { recursive: true });
        const ignoreFile = path.join(dir, '.gitignore');
        if (!fs.existsSync(ignoreFile)) {
            try { fs.writeFileSync(ignoreFile, '*\n', 'utf8'); } catch { /* best effort */ }
        }
        const fileName = `${safeId}.json`;
        fs.writeFileSync(path.join(dir, fileName), JSON.stringify(sanitizeArtifact(artifact), null, 2), 'utf8');
        try { rotate(dir, fileName); } catch { /* best effort */ }
        return `${PROOF_ARTIFACT_DIR}/${fileName}`.split(path.sep).join('/');
    } catch {
        return null;
    }
}
