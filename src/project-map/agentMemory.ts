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
const MEMORY_VERSION = 2;
const MAX_FALSE_POSITIVES = 100;  // cap to prevent unbounded growth
const MAX_KNOWN_FACTS = 50;
const MAX_INVESTIGATION_NOTES = 50;
const MAX_COVERAGE_GAPS = 30;
const MEMORY_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

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

export interface InvestigationMemoryEntry {
    id: string;
    kind: 'investigation-note';
    title: string;
    detail: string;
    file: string;
    line?: number;
    lineEnd?: number;
    symbol?: string;
    verificationLevel: string;
    rootCauseId?: string;
    requiredEvidence: string[];
    priority: 'high' | 'medium' | 'low';
    sourceScanId?: string;
    fileHash?: string;
    createdAt: string;
    lastSeenAt: string;
    status: 'open' | 'resolved' | 'stale';
}

export interface CoverageGapMemoryEntry {
    id: string;
    kind: 'coverage-gap';
    title: string;
    detail: string;
    file?: string;
    line?: number;
    lineEnd?: number;
    symbol?: string;
    requiredEvidence: string[];
    suggestedNextAction: string;
    priority: 'high' | 'medium' | 'low';
    sourceScanId?: string;
    fileHash?: string;
    createdAt: string;
    lastSeenAt: string;
    status: 'open' | 'resolved' | 'stale';
}

export interface AgentMemory {
    version: number;
    falsePositives: FalsePositiveEntry[];
    knownFacts: KnownFactEntry[];
    investigationNotes: InvestigationMemoryEntry[];
    coverageGaps: CoverageGapMemoryEntry[];
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
            return { version: MEMORY_VERSION, falsePositives: [], knownFacts: [], investigationNotes: [], coverageGaps: [] };
        }
        const raw = fs.readFileSync(p, 'utf8');
        const data = JSON.parse(raw) as Partial<AgentMemory>;
        if (!data.version || data.version > MEMORY_VERSION) {
            return { version: MEMORY_VERSION, falsePositives: [], knownFacts: [], investigationNotes: [], coverageGaps: [] };
        }
        return {
            version: MEMORY_VERSION,
            falsePositives: data.falsePositives || [],
            knownFacts: data.knownFacts || [],
            investigationNotes: data.investigationNotes || [],
            coverageGaps: data.coverageGaps || [],
        };
    } catch {
        return { version: MEMORY_VERSION, falsePositives: [], knownFacts: [], investigationNotes: [], coverageGaps: [] };
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
 * Clear all agent memory (false positives + known facts + notes + gaps) for a workspace.
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

// ── Investigation notes and coverage gaps persistence ────────────────────────

export interface SaveInvestigationNotesInput {
    notes: Array<{
        title: string;
        detail: string;
        file: string;
        line?: number;
        lineEnd?: number;
        symbol?: string;
        verificationLevel: string;
        rootCauseId?: string;
        requiredEvidence: string[];
        priority: 'high' | 'medium' | 'low';
    }>;
    sourceScanId?: string;
    fileHashes?: Map<string, string>;
}

export function saveInvestigationNotes(
    workspaceRoot: string,
    input: SaveInvestigationNotesInput,
): void {
    if (!input.notes || input.notes.length === 0) return;
    const memory = loadAgentMemory(workspaceRoot);
    const now = new Date().toISOString();

    for (const note of input.notes) {
        const fileHash = input.fileHashes?.get(note.file);
        const existingIdx = memory.investigationNotes.findIndex(
            n => n.file === note.file && n.title === note.title && n.status === 'open',
        );
        if (existingIdx >= 0) {
            memory.investigationNotes[existingIdx].lastSeenAt = now;
            memory.investigationNotes[existingIdx].detail = note.detail;
            memory.investigationNotes[existingIdx].requiredEvidence = note.requiredEvidence;
            memory.investigationNotes[existingIdx].fileHash = fileHash ?? memory.investigationNotes[existingIdx].fileHash;
            continue;
        }

        memory.investigationNotes.push({
            id: 'note_' + crypto.randomBytes(4).toString('hex'),
            kind: 'investigation-note',
            title: note.title,
            detail: note.detail,
            file: note.file,
            line: note.line,
            lineEnd: note.lineEnd,
            symbol: note.symbol,
            verificationLevel: note.verificationLevel,
            rootCauseId: note.rootCauseId,
            requiredEvidence: note.requiredEvidence,
            priority: note.priority,
            sourceScanId: input.sourceScanId,
            fileHash,
            createdAt: now,
            lastSeenAt: now,
            status: 'open',
        });
    }

    pruneExpired(memory);
    if (memory.investigationNotes.length > MAX_INVESTIGATION_NOTES) {
        memory.investigationNotes = memory.investigationNotes.slice(-MAX_INVESTIGATION_NOTES);
    }
    saveAgentMemory(workspaceRoot, memory);
}

export interface SaveCoverageGapsInput {
    gaps: Array<{
        title: string;
        detail: string;
        file?: string;
        line?: number;
        lineEnd?: number;
        symbol?: string;
        requiredEvidence: string[];
        suggestedNextAction: string;
        priority: 'high' | 'medium' | 'low';
    }>;
    sourceScanId?: string;
    fileHashes?: Map<string, string>;
}

export function saveCoverageGaps(
    workspaceRoot: string,
    input: SaveCoverageGapsInput,
): void {
    if (!input.gaps || input.gaps.length === 0) return;
    const memory = loadAgentMemory(workspaceRoot);
    const now = new Date().toISOString();

    for (const gap of input.gaps) {
        const file = gap.file;
        const fileHash = file ? input.fileHashes?.get(file) : undefined;
        const existingIdx = file
            ? memory.coverageGaps.findIndex(
                g => g.file === file && g.title === gap.title && g.status === 'open',
            )
            : -1;
        if (existingIdx >= 0) {
            memory.coverageGaps[existingIdx].lastSeenAt = now;
            memory.coverageGaps[existingIdx].detail = gap.detail;
            memory.coverageGaps[existingIdx].requiredEvidence = gap.requiredEvidence;
            memory.coverageGaps[existingIdx].fileHash = fileHash ?? memory.coverageGaps[existingIdx].fileHash;
            continue;
        }

        memory.coverageGaps.push({
            id: 'gap_' + crypto.randomBytes(4).toString('hex'),
            kind: 'coverage-gap',
            title: gap.title,
            detail: gap.detail,
            file,
            line: gap.line,
            lineEnd: gap.lineEnd,
            symbol: gap.symbol,
            requiredEvidence: gap.requiredEvidence,
            suggestedNextAction: gap.suggestedNextAction,
            priority: gap.priority,
            sourceScanId: input.sourceScanId,
            fileHash,
            createdAt: now,
            lastSeenAt: now,
            status: 'open',
        });
    }

    pruneExpired(memory);
    if (memory.coverageGaps.length > MAX_COVERAGE_GAPS) {
        memory.coverageGaps = memory.coverageGaps.slice(-MAX_COVERAGE_GAPS);
    }
    saveAgentMemory(workspaceRoot, memory);
}

/**
 * Mark investigation notes and coverage gaps as stale when their referenced
 * file has changed (hash mismatch). Called before a new scan starts so the
 * agent sees accurate context.
 */
export function invalidateStaleEntries(
    workspaceRoot: string,
    currentFileHashes: Map<string, string>,
): void {
    const memory = loadAgentMemory(workspaceRoot);
    let changed = false;

    for (const note of memory.investigationNotes) {
        if (note.status !== 'open') continue;
        if (!note.fileHash) continue;
        const currentHash = currentFileHashes.get(note.file);
        if (currentHash && currentHash !== note.fileHash) {
            note.status = 'stale';
            changed = true;
        }
    }

    for (const gap of memory.coverageGaps) {
        if (gap.status !== 'open') continue;
        if (!gap.fileHash || !gap.file) continue;
        const currentHash = currentFileHashes.get(gap.file);
        if (currentHash && currentHash !== gap.fileHash) {
            gap.status = 'stale';
            changed = true;
        }
    }

    if (changed) {
        pruneExpired(memory);
        saveAgentMemory(workspaceRoot, memory);
    }
}

/**
 * Mark a note or gap as resolved (the concern was addressed in a later scan).
 */
export function resolveMemoryEntry(
    workspaceRoot: string,
    entryId: string,
): boolean {
    const memory = loadAgentMemory(workspaceRoot);
    let found = false;
    for (const note of memory.investigationNotes) {
        if (note.id === entryId) {
            note.status = 'resolved';
            found = true;
        }
    }
    for (const gap of memory.coverageGaps) {
        if (gap.id === entryId) {
            gap.status = 'resolved';
            found = true;
        }
    }
    if (found) saveAgentMemory(workspaceRoot, memory);
    return found;
}

function pruneExpired(memory: AgentMemory): void {
    const now = Date.now();
    memory.investigationNotes = memory.investigationNotes.filter(n => {
        const age = now - new Date(n.lastSeenAt).getTime();
        return age < MEMORY_TTL_MS;
    });
    memory.coverageGaps = memory.coverageGaps.filter(g => {
        const age = now - new Date(g.lastSeenAt).getTime();
        return age < MEMORY_TTL_MS;
    });
}

// ── Prompt formatting ───────────────────────────────────────────────────────

/**
 * Format agent memory into a string block for injection into the agent's
 * target context. Returns empty string if no memory.
 */
export function formatMemoryForPrompt(memory: AgentMemory): string {
    const hasFps = memory.falsePositives.length > 0;
    const hasFacts = memory.knownFacts.length > 0;
    const openNotes = memory.investigationNotes.filter(n => n.status === 'open');
    const openGaps = memory.coverageGaps.filter(g => g.status === 'open');
    const staleNotes = memory.investigationNotes.filter(n => n.status === 'stale');
    const staleGaps = memory.coverageGaps.filter(g => g.status === 'stale');
    if (!hasFps && !hasFacts && openNotes.length === 0 && openGaps.length === 0 && staleNotes.length === 0 && staleGaps.length === 0) return '';

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

    if (openNotes.length > 0) {
        lines.push('', `Prior unresolved investigation notes — re-check against current code, do NOT assume they are still valid (${openNotes.length}):`);
        openNotes.forEach((n, i) => {
            lines.push(`  ${i + 1}. [${n.priority}] ${n.title}`);
            lines.push(`     ${n.detail}`);
            if (n.file) lines.push(`     File: ${n.file}${n.line ? `:${n.line}` : ''}`);
            if (n.requiredEvidence.length > 0) lines.push(`     Still needed: ${n.requiredEvidence.join('; ')}`);
        });
    }

    if (openGaps.length > 0) {
        lines.push('', `Prior coverage gaps — investigate these if the target file is related (${openGaps.length}):`);
        openGaps.forEach((g, i) => {
            lines.push(`  ${i + 1}. [${g.priority}] ${g.title}`);
            lines.push(`     ${g.detail}`);
            if (g.file) lines.push(`     File: ${g.file}${g.line ? `:${g.line}` : ''}`);
            lines.push(`     Next action: ${g.suggestedNextAction}`);
        });
    }

    if (staleNotes.length > 0 || staleGaps.length > 0) {
        lines.push('', `Stale entries (file changed since last scan — re-investigate from scratch):`);
        staleNotes.forEach(n => lines.push(`  - [note] ${n.title} (${n.file})`));
        staleGaps.forEach(g => lines.push(`  - [gap] ${g.title} (${g.file || 'unknown'})`));
    }

    return lines.join('\n');
}
