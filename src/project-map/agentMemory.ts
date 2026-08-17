/**
 * Agent memory — per-workspace store of false positives and known facts.
 *
 * The agent reads this at the start of each scan so it doesn't repeat
 * mistakes from prior scans. False positives are patterns the user has
 * explicitly dismissed; known facts are structural facts about the project
 * (e.g. "uses requireMembership for auth") that speed up investigation.
 *
 * Storage: <workspaceRoot>/.securecode/agent-memory.json
 * Pattern: same as scanCache.ts — lazy mkdir, atomic write (.tmp + rename).
 *
 * Privacy: per-workspace only. No cross-tenant leakage. User-owned, deletable.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

const MEMORY_DIR = '.securecode';
const MEMORY_FILE = 'agent-memory.json';
const MEMORY_VERSION = 1;
const MAX_FALSE_POSITIVES = 100;  // cap to prevent unbounded growth
const MAX_KNOWN_FACTS = 50;

// ── Types ───────────────────────────────────────────────────────────────────

export interface FalsePositiveEntry {
    id: string;
    findingType: string;
    file: string;
    line: number;
    /** SHA-256 of the evidence string — for dedup. */
    evidenceHash: string;
    /** Short pattern description for the prompt. */
    pattern: string;
    /** User's reason for dismissing. */
    reason: string;
    /** Code snippet (truncated) for context. */
    codeSnippet?: string;
    addedAt: string;  // ISO timestamp
}

export interface KnownFactEntry {
    id: string;
    fact: string;
    source: string;  // file:line
    addedAt: string;
}

export interface AgentMemory {
    version: number;
    falsePositives: FalsePositiveEntry[];
    knownFacts: KnownFactEntry[];
}

// ── Path helpers ────────────────────────────────────────────────────────────

function memoryPath(workspaceRoot: string): string {
    return path.join(workspaceRoot, MEMORY_DIR, MEMORY_FILE);
}

function hashEvidence(evidence: string): string {
    return crypto.createHash('sha256').update(evidence).digest('hex').slice(0, 16);
}

function genId(): string {
    return 'fp_' + crypto.randomBytes(4).toString('hex');
}

// ── Read / Write ────────────────────────────────────────────────────────────

/**
 * Load agent memory for a workspace. Returns an empty memory object
 * (version + empty arrays) if the file doesn't exist or is corrupt.
 */
export function loadAgentMemory(workspaceRoot: string): AgentMemory {
    const p = memoryPath(workspaceRoot);
    try {
        if (!fs.existsSync(p)) {
            return { version: MEMORY_VERSION, falsePositives: [], knownFacts: [] };
        }
        const raw = fs.readFileSync(p, 'utf8');
        const data = JSON.parse(raw) as AgentMemory;
        if (!data.version || data.version > MEMORY_VERSION) {
            // Forward-incompatible — start fresh
            return { version: MEMORY_VERSION, falsePositives: [], knownFacts: [] };
        }
        return {
            version: MEMORY_VERSION,
            falsePositives: data.falsePositives || [],
            knownFacts: data.knownFacts || [],
        };
    } catch {
        return { version: MEMORY_VERSION, falsePositives: [], knownFacts: [] };
    }
}

/** Save agent memory (atomic write). */
function saveAgentMemory(workspaceRoot: string, memory: AgentMemory): void {
    const dir = path.join(workspaceRoot, MEMORY_DIR);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    const p = memoryPath(workspaceRoot);
    const tmp = p + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(memory, null, 2), 'utf8');
    fs.renameSync(tmp, p);
}

// ── Public API ──────────────────────────────────────────────────────────────

export interface RecordFalsePositiveInput {
    filePath: string;
    findingType: string;
    line: number;
    evidence: string;
    reason: string;
    pattern?: string;       // optional — if not given, derived from evidence
    codeSnippet?: string;
}

/**
 * Record a false positive. Dedupes by (findingType + evidenceHash).
 * Returns the entry (existing or new). Returns null if input is invalid.
 */
export function recordFalsePositive(
    workspaceRoot: string,
    input: RecordFalsePositiveInput,
): FalsePositiveEntry | null {
    if (!input.filePath || !input.findingType || !input.evidence || !input.reason) {
        return null;
    }

    const memory = loadAgentMemory(workspaceRoot);
    const evidenceHash = hashEvidence(input.evidence);

    // Dedup: if the same finding type + evidence hash exists, update the reason
    const existingIdx = memory.falsePositives.findIndex(
        fp => fp.findingType === input.findingType && fp.evidenceHash === evidenceHash
    );
    if (existingIdx >= 0) {
        memory.falsePositives[existingIdx].reason = input.reason;
        memory.falsePositives[existingIdx].pattern = input.pattern || memory.falsePositives[existingIdx].pattern;
        saveAgentMemory(workspaceRoot, memory);
        return memory.falsePositives[existingIdx];
    }

    const entry: FalsePositiveEntry = {
        id: genId(),
        findingType: input.findingType,
        file: input.filePath,
        line: input.line,
        evidenceHash,
        pattern: input.pattern || input.evidence.slice(0, 200),
        reason: input.reason,
        codeSnippet: input.codeSnippet ? input.codeSnippet.slice(0, 500) : undefined,
        addedAt: new Date().toISOString(),
    };

    memory.falsePositives.push(entry);

    // Cap growth — drop oldest
    if (memory.falsePositives.length > MAX_FALSE_POSITIVES) {
        memory.falsePositives = memory.falsePositives.slice(-MAX_FALSE_POSITIVES);
    }

    saveAgentMemory(workspaceRoot, memory);
    return entry;
}

/**
 * Remove a false positive by ID. Returns true if removed.
 */
export function removeFalsePositive(workspaceRoot: string, id: string): boolean {
    const memory = loadAgentMemory(workspaceRoot);
    const before = memory.falsePositives.length;
    memory.falsePositives = memory.falsePositives.filter(fp => fp.id !== id);
    if (memory.falsePositives.length === before) return false;
    saveAgentMemory(workspaceRoot, memory);
    return true;
}

/**
 * Add a known fact. Dedupes by fact text (case-insensitive).
 */
export function addKnownFact(
    workspaceRoot: string,
    fact: string,
    source: string,
): KnownFactEntry | null {
    if (!fact || !source) return null;
    const memory = loadAgentMemory(workspaceRoot);
    const lower = fact.toLowerCase().trim();
    if (memory.knownFacts.some(kf => kf.fact.toLowerCase().trim() === lower)) {
        return null;  // already exists
    }
    const entry: KnownFactEntry = {
        id: 'fact_' + crypto.randomBytes(4).toString('hex'),
        fact,
        source,
        addedAt: new Date().toISOString(),
    };
    memory.knownFacts.push(entry);
    if (memory.knownFacts.length > MAX_KNOWN_FACTS) {
        memory.knownFacts = memory.knownFacts.slice(-MAX_KNOWN_FACTS);
    }
    saveAgentMemory(workspaceRoot, memory);
    return entry;
}

/**
 * Clear all agent memory (false positives + known facts) for a workspace.
 */
export function clearAgentMemory(workspaceRoot: string): boolean {
    const p = memoryPath(workspaceRoot);
    try {
        if (fs.existsSync(p)) {
            fs.unlinkSync(p);
            return true;
        }
        return false;
    } catch {
        return false;
    }
}

// ── Prompt formatting ───────────────────────────────────────────────────────

/**
 * Format agent memory into a string block for injection into the agent's
 * target context. Returns empty string if no memory.
 */
export function formatMemoryForPrompt(memory: AgentMemory): string {
    const hasFps = memory.falsePositives.length > 0;
    const hasFacts = memory.knownFacts.length > 0;
    if (!hasFps && !hasFacts) return '';

    const lines: string[] = ['Workspace memory (from previous scans in this workspace):'];

    if (hasFps) {
        lines.push('', `False positives — DO NOT report similar patterns (${memory.falsePositives.length}):`);
        memory.falsePositives.forEach((fp, i) => {
            lines.push(`  ${i + 1}. [${fp.findingType}] "${fp.pattern}"`);
            lines.push(`     Reason: ${fp.reason}`);
            if (fp.file) lines.push(`     Was at: ${fp.file}:${fp.line}`);
        });
        lines.push('', 'Before reporting a finding, check if it matches any false positive above.');
        lines.push('If the finding type AND code pattern match a known FP, do NOT report it.');
    }

    if (hasFacts) {
        lines.push('', `Known facts about this project (${memory.knownFacts.length}):`);
        memory.knownFacts.forEach((f, i) => {
            lines.push(`  ${i + 1}. ${f.fact} (source: ${f.source})`);
        });
    }

    return lines.join('\n');
}
