/**
 * Hard finish gate — rejects premature finish attempts and continues the
 * investigation while executable work and budget remain.
 *
 * The finish gate is MCP-owned. When the model proposes `finish`, the gate
 * evaluates whether the investigation is actually complete:
 *
 * - Required checklist steps must be complete
 * - Architecture-risk tasks must be resolved, refuted, or blocked
 * - All candidates must be terminal
 * - Security-sensitive handlers must be reviewed
 * - No executable work items remain (when budget is available)
 *
 * If any of these conditions fail and budget remains, finish is REJECTED
 * and the gate returns a recovery action to continue the investigation.
 *
 * If budget is exhausted, finish is accepted as "forced-incomplete" with
 * coverage gaps for every unresolved item.
 */

import type { AgentLead, AgentScanAction, AgentScanFinding, AgentScanFinishAction, AgentScanTranscriptStep, GridCell } from './agentScanProtocol';
import { AGENT_SCAN_DEFAULTS } from './agentScanProtocol';
import type { ScanRunState } from './scanState';
import type { GridGateProblems } from '../assurance/gridState';
import type { EvidenceLedger } from './evidenceLedger';
import type { WorkItemQueue } from './workItem';
import type { HandlerInventory } from '../project-map/handlerInventory';
import type { Candidate, CandidateStore } from './candidateStore';
import { missingGateDimensions, FLOW_LINE_TOLERANCE } from './candidateStore';
import { uncoveredWithin, type InvestigationState, type LineRange } from './investigationState';
import type { ScheduleDecision } from './scanScheduler';
import { hasStructureSupport } from '../project-map/capabilityRegistry';

export type FinishGateMode = 'complete' | 'continue' | 'forced-incomplete';

export const LOGIC_BUG_TYPES = new Set([
    'broken_access_control', 'idor', 'privilege_escalation', 'mass_assignment',
    'business_logic', 'state_order', 'race_condition', 'auth_bypass',
    'broken_authentication', 'missing_authorization', 'insecure_default',
    'config_default',
]);

export const FLOW_REQUIRED_TYPES = new Set([
    'sql_injection', 'nosql_injection', 'command_injection', 'code_injection',
    'xss', 'ssrf', 'path_traversal', 'open_redirect', 'prototype_pollution',
    'insecure_deserialization', 'template_injection', 'ldap_injection',
    'xpath_injection', 'header_injection', 'log_injection', 'xxe',
]);

function isLogicClass(candidateType: string): boolean {
    const normalized = candidateType.toLowerCase().replace(/[\s-]+/g, '_');
    for (const logicType of LOGIC_BUG_TYPES) {
        if (normalized.includes(logicType)) return true;
    }
    for (const flowType of FLOW_REQUIRED_TYPES) {
        if (normalized.includes(flowType)) return false;
    }
    return !/injection|traversal|xss|ssrf|redirect|deserializ/.test(normalized);
}

function candidateLinesDelivered(
    candidate: Candidate,
    investigation: InvestigationState,
    targetFile?: string,
    deliveredRanges?: LineRange[],
): { entryDelivered: boolean; vulnDelivered: boolean } {
    if (candidate.locations.length === 0) return { entryDelivered: false, vulnDelivered: false };
    let entryDelivered = false;
    let vulnDelivered = false;
    for (const loc of candidate.locations) {
        const inPrompt = !!targetFile && loc.filePath === targetFile
            && (deliveredRanges ?? []).some(r => loc.line >= r.start && loc.line <= r.end);
        if (inPrompt || investigation.isCovered(loc.filePath, loc.line, loc.line)) {
            vulnDelivered = true;
            entryDelivered = true;
        }
    }
    return { entryDelivered, vulnDelivered };
}

const ACTOR_TERMS = ['attacker', 'user', 'member', 'caller', 'client', 'unauthenticated', 'authenticated', 'any user', 'actor', 'adversary', 'requester', 'anyone', 'anonymous', 'someone', 'visitor', 'tenant', 'account', 'request', 'public', 'customer', 'owner', 'buyer', 'seller', 'admin', 'employee', 'guest', 'holder', 'sender', 'recipient', 'operator', 'staff', 'merchant', 'partner', 'reviewer'];
const EFFECT_TERMS = ['escalat', 'elevat', 'overwrit', 'bypass', 'impersonat', 'admin', 'role', 'permission', 'privilege', 'unauthoriz', 'access', 'modify', 'manipulat', 'tamper', 'inject', 'assign', 'set', 'update', 'change', 'forge', 'leak', 'expos', 'disclos', 'enumerat', 'reveal', 'find out', 'learn', 'crash', 'denial', 'exhaust', 'hang', 'block', 'delete', 'duplicate', 'take over', 'takeover', 'steal', 'read', 'sign', 'gain', 'grant', 'give', 'upgrade', 'obtain', 'without pay', 'for free', 'unlock', 'backtrack', 'freez', 'stall', 'slow', 'cpu', 'memory', 'event loop', 'timeout', 'capabilit', 'cancel', 'refund', 'shipped', 'shipping', 'transfer', 'withdraw', 'send', 'mark', 'paid', 'pay', 'price', 'cost', 'amount'];

export function textHasActorAndEffect(text: string): boolean {
    const lower = text.toLowerCase();
    const hasActor = ACTOR_TERMS.some(t => {
        const idx = lower.indexOf(t);
        if (idx === -1) return false;
        const rest = lower.slice(idx + t.length);
        if (rest.length > 0 && /^[a-z]/.test(rest) && !/^(s\b|es\b|'s\b)/.test(rest)) return false;
        return true;
    });
    const hasEffect = EFFECT_TERMS.some(t => lower.includes(t));
    return hasActor && hasEffect;
}

function candidateClaimHasActorAndEffect(candidate: Candidate): boolean {
    return textHasActorAndEffect(candidate.claim || '');
}

function findMatchingFinding(candidate: Candidate, findings: AgentScanFinding[]): AgentScanFinding | undefined {
    for (const finding of findings) {
        if (candidate.rootCauseId === `${finding.type}:${finding.line}`) return finding;
        if (finding.rootCause?.rootCauseId && candidate.rootCauseId === finding.rootCause.rootCauseId) return finding;
        for (const loc of candidate.locations) {
            if (finding.type === candidate.type && Math.abs(finding.line - loc.line) <= FLOW_LINE_TOLERANCE) return finding;
        }
    }
    return undefined;
}

function findingTextHasActorAndEffect(finding: AgentScanFinding): boolean {
    const texts = [finding.why || '', finding.evidence || ''];
    return texts.some(t => textHasActorAndEffect(t));
}

function sinkKeywordsForType(candidateType: string): string[] {
    const norm = candidateType.toLowerCase().replace(/[\s-]+/g, '_');
    if (norm.includes('sql_injection') || norm.includes('nosql_injection')) return ['sql', 'query', 'select', 'insert', 'update', 'delete', 'drop', 'table'];
    if (norm.includes('command_injection') || norm.includes('code_injection')) return ['exec', 'spawn', 'eval', 'shell', 'command'];
    if (norm.includes('xss')) return ['script', 'alert', 'onerror', 'innerhtml', 'document.write'];
    if (norm.includes('ssrf')) return ['fetch', 'request', 'http', 'url'];
    if (norm.includes('path_traversal')) return ['readfile', 'readfilesync', 'path', '..', 'directory'];
    if (norm.includes('template_injection')) return ['template', 'render', 'compile'];
    if (norm.includes('xxe')) return ['xml', 'parse', 'entity'];
    if (norm.includes('ldap_injection')) return ['ldap', 'bind', 'search'];
    if (norm.includes('xpath_injection')) return ['xpath', 'evaluate'];
    if (norm.includes('header_injection') || norm.includes('log_injection')) return ['header', 'log', 'write'];
    if (norm.includes('open_redirect')) return ['redirect', 'location', 'url'];
    if (norm.includes('prototype_pollution')) return ['prototype', '__proto__', 'constructor'];
    if (norm.includes('insecure_deserialization')) return ['deserializ', 'unserializ', 'json.parse', 'pickle'];
    return [];
}

export function transcriptHasRuntimeEvidence(
    candidate: Candidate,
    transcript: AgentScanTranscriptStep[],
): boolean {
    const keywords = sinkKeywordsForType(candidate.type);
    if (keywords.length === 0) return false;
    const candidateLine = candidate.locations[0]?.line;
    for (const step of transcript) {
        if ((step.action as any)?.type !== 'run_tests') continue;
        const obs = (step.observation || '').toLowerCase();
        if (!obs.includes('passed') && !obs.includes('pass:') && !obs.includes('exit code: 0')) continue;
        const lineMatch = candidateLine && obs.includes(`line ${candidateLine}`);
        const keywordMatch = keywords.some(kw => obs.includes(kw));
        if (lineMatch || keywordMatch) return true;
    }
    return false;
}

function checkGuardSatisfiesControl(
    candidate: Candidate,
    transcript: AgentScanTranscriptStep[],
): boolean {
    for (const step of transcript) {
        if ((step.action as any)?.type !== 'check_guard') continue;
        const obs = step.observation || '';
        const obsLower = obs.toLowerCase();
        const candidateFile = candidate.locations[0]?.filePath || '';
        const candidateFileNorm = candidateFile.replace(/\\/g, '/').toLowerCase();
        const actionFile = ((step.action as any)?.filePath || '').replace(/\\/g, '/').toLowerCase();
        if (candidateFileNorm && actionFile && !candidateFileNorm.endsWith(actionFile) && !actionFile.endsWith(candidateFileNorm)) continue;
        if (obsLower.includes('not effective') || obsLower.includes('not_effective') ||
            obsLower.includes('unknown') || obsLower.includes('no guard') ||
            obsLower.includes('ineffective')) {
            return true;
        }
        if (obsLower.includes('effective')) {
            return true;
        }
    }
    return false;
}

/**
 * When the identical reason-code set rejects this many CONSECUTIVE finishes,
 * the loop accepts the next finish as forced-incomplete (the same salvage
 * semantics as the 75% soft deadline) instead of grinding to the wall clock.
 * Production showed a candidate-blocked agent proposing finish ~16 times with
 * the recovery loop unable to converge — 33 minutes of burn for one finding.
 */
export const FINISH_LOOP_ESCAPE_THRESHOLD = 4;

/**
 * Lower threshold when the only blockers are checklist items (unsatisfied
 * evidence requirements / incomplete checklist steps) and nothing of
 * substance is pending — no candidates and no high-priority unread range.
 * Each rejection costs about two steps; grinding four of them on a
 * checklist that may not apply to the file wastes the budget.
 */
export const FINISH_LOOP_CHECKLIST_ESCAPE_THRESHOLD = 2;

/**
 * Candidate-only rejections (every reason is `non-terminal-candidate`) also
 * escape after two identical rejections: the open dimensions are recorded
 * as the finding's required evidence and the verifier runs after finish.
 */
export const FINISH_LOOP_CANDIDATE_ESCAPE_THRESHOLD = 2;

const CHECKLIST_ONLY_REASON_CODES = new Set(['unsatisfied-evidence-requirement', 'incomplete-checklist']);

export const HIGH_PRIORITY_KEYWORDS = [
    'authenticat', 'authorize', 'authorization', 'token', 'session',
    'credential', 'password', 'execfile', 'exec(', 'spawn(',
    'child_process', 'writefile', 'permission', 'ownership',
    'bootstrap', 'pairing', 'sql', 'queryraw', 'eval(',
];

export function rangeHasHighPriorityCode(fileContent: string | undefined, range: { start: number; end: number }): boolean {
    if (!fileContent) return false;
    const lines = fileContent.split('\n');
    const rangeText = lines.slice(Math.max(0, range.start - 1), Math.min(lines.length, range.end)).join('\n').toLowerCase();
    return HIGH_PRIORITY_KEYWORDS.some(kw => rangeText.includes(kw));
}

export interface FinishLoopTracker {
    rejections: number;
    signature: string;
    threshold: number;
}

export function newFinishLoopTracker(): FinishLoopTracker {
    return { rejections: 0, signature: '', threshold: FINISH_LOOP_ESCAPE_THRESHOLD };
}

export function finishLoopEscapeThreshold(reasons: FinishGateReason[], activeCandidateCount = 0): number {
    if (reasons.length === 0) return FINISH_LOOP_ESCAPE_THRESHOLD;
    if (reasons.every(r => r.code === 'non-terminal-candidate')) return FINISH_LOOP_CANDIDATE_ESCAPE_THRESHOLD;
    const checklistOnly = reasons.every(r => CHECKLIST_ONLY_REASON_CODES.has(r.code));
    return checklistOnly && activeCandidateCount === 0
        ? FINISH_LOOP_CHECKLIST_ESCAPE_THRESHOLD
        : FINISH_LOOP_ESCAPE_THRESHOLD;
}

/**
 * Record a rejected finish against the tracker. An identical reason-code
 * signature climbs the counter; a changed signature means the investigation
 * is still making progress (fewer/different blockers) and resets it.
 */
export function trackFinishRejection(tracker: FinishLoopTracker, reasons: FinishGateReason[], activeCandidateCount = 0): FinishLoopTracker {
    const signature = reasons.map(r => r.code).sort().join('|');
    if (signature === tracker.signature) {
        tracker.rejections++;
    } else {
        tracker.rejections = 1;
        tracker.signature = signature;
    }
    tracker.threshold = finishLoopEscapeThreshold(reasons, activeCandidateCount);
    return tracker;
}

export function finishLoopEscaped(tracker: FinishLoopTracker): boolean {
    return tracker.rejections >= (tracker.threshold ?? FINISH_LOOP_ESCAPE_THRESHOLD);
}

/**
 * Landing mode: no more credits can be added to the run and the remaining
 * cost budget covers fewer than three steps. Mirrors the API rule so an
 * older API that does not send `landing` still lets the run land.
 */
export function isLandingBudget(
    serverBudget: { creditsUsed: number; maxCredits: number; costSpentUsd: number; costCapUsd: number } | undefined,
    perStepEstimateUsd: number = AGENT_SCAN_DEFAULTS.perStepEstimateUsd,
    extensionCredits: number = AGENT_SCAN_DEFAULTS.extensionCredits,
): boolean {
    if (!serverBudget) return false;
    const { creditsUsed, maxCredits, costSpentUsd, costCapUsd } = serverBudget;
    if (![creditsUsed, maxCredits, costSpentUsd, costCapUsd].every(v => typeof v === 'number' && Number.isFinite(v))) return false;
    return creditsUsed + extensionCredits > maxCredits && costCapUsd - costSpentUsd < 3 * perStepEstimateUsd;
}

export interface FinishGateReason {
    code: string;
    description: string;
}

export interface FinishGateCoverageGap {
    title: string;
    detail: string;
    file: string;
    line?: number;
    lineEnd?: number;
    requiredEvidence: string[];
    suggestedNextAction: string;
    priority: 'high' | 'medium' | 'low';
}

export interface FinishGateResult {
    accepted: boolean;
    mode: FinishGateMode;
    reasons: FinishGateReason[];
    recoveryAction?: AgentScanAction;
    normalizedFinish?: AgentScanFinishAction;
    coverageGaps?: FinishGateCoverageGap[];
}

/** Inputs for the evidence-mode gate (harness gateMode 'evidence'). */
export interface EvidenceGateInput {
    /** Latest non-null leads the agent reported. */
    currentLeads: AgentLead[];
    /** Target-file lines delivered to the agent: read coverage plus the source shown in the prompt. */
    deliveredRanges: LineRange[];
    /** The lines this run must cover: the part of a split file, or the whole file. */
    targetRange: LineRange;
    openLeadsRejectedOnce: boolean;
    /** Findings to check against delivered lines; defaults to the proposal's findings. */
    findings?: AgentScanFinding[];
    /** Connected files from the file inventory (deep mode). */
    connectedFiles?: Array<{ file: string; relation: string; reason: string }>;
    /** Grid cells for the assurance grid (deep mode). */
    gridCells?: GridCell[];
    /** Number of times the connected/grid requirements have been rejected. */
    doneRuleRejections?: number;
}

export interface FinishGateInput {
    proposal: AgentScanFinishAction;
    state: ScanRunState;
    evidence: EvidenceLedger;
    workItems: WorkItemQueue;
    handlers: HandlerInventory;
    candidates: CandidateStore;
    investigation: InvestigationState;
    scheduler: ScheduleDecision;
    target: { filePath: string; fileContent?: string; segment?: { startLine: number; endLine: number }; language?: string };
    landing?: boolean;
    gateMode?: 'checklist' | 'evidence';
    evidenceGate?: EvidenceGateInput;
    assuranceGate?: AssuranceGateInput;
    transcript?: AgentScanTranscriptStep[];
}

export interface AssuranceGateInput {
    problems: GridGateProblems;
    isFullyClosed: boolean;
    redteamDone: boolean;
}

export const INVESTIGATION_FLOOR_FRACTION = 0.5;
const MAX_LISTED_OPEN_LEADS = 10;

function leadListedInGaps(lead: AgentLead, gaps: AgentScanFinishAction['coverageGaps']): boolean {
    if (!Array.isArray(gaps) || gaps.length === 0) return false;
    const claim = String(lead.claim || '').trim().toLowerCase();
    const id = String(lead.id || '').trim().toLowerCase();
    return gaps.some(g => {
        const text = `${g?.title ?? ''} ${g?.detail ?? ''}`.toLowerCase();
        if (claim.length > 0 && text.includes(claim)) return true;
        return id.length > 0 && new RegExp(`(^|[^a-z0-9_-])${id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9_-]|$)`).test(text);
    });
}

/** Open leads the finish neither resolved nor listed in its coverage gaps. */
export function unresolvedOpenLeads(leads: AgentLead[] | null | undefined, proposal?: Pick<AgentScanFinishAction, 'coverageGaps'>): AgentLead[] {
    if (!Array.isArray(leads)) return [];
    return leads.filter(l =>
        !!l && typeof l === 'object' && l.status === 'open' &&
        typeof l.claim === 'string' && l.claim.trim().length > 0 &&
        !leadListedInGaps(l, proposal?.coverageGaps));
}

export const LEAD_GAP_TITLE_PREFIX = 'Lead not resolved: ';

export function leadCoverageGap(lead: AgentLead, filePath: string): FinishGateCoverageGap {
    const line = typeof lead.line === 'number' && Number.isFinite(lead.line) && lead.line > 0 ? lead.line : undefined;
    return {
        title: `${LEAD_GAP_TITLE_PREFIX}${lead.claim.trim()}`,
        detail: `The agent opened this lead${line ? ` at line ${line}` : ''} and finished without resolving it${lead.resolution ? ` (last note: ${lead.resolution})` : ''}.`,
        file: filePath,
        ...(line ? { line } : {}),
        requiredEvidence: [`Confirm or rule out: ${lead.claim.trim()}`],
        suggestedNextAction: line ? `read_file around line ${line}` : 'continue investigation',
        priority: 'medium',
    };
}

function describeLead(lead: AgentLead): string {
    const line = typeof lead.line === 'number' && Number.isFinite(lead.line) && lead.line > 0 ? ` (line ${lead.line})` : '';
    const id = lead.id ? `${lead.id}: ` : '';
    return `${id}${lead.claim.trim()}${line}`;
}

function formatRange(r: LineRange): string {
    return r.start === r.end ? `${r.start}` : `${r.start}–${r.end}`;
}

function evaluateEvidenceChecks(
    input: FinishGateInput,
    gate: EvidenceGateInput,
    canReject: boolean,
    reasons: FinishGateReason[],
    coverageGaps: FinishGateCoverageGap[],
): void {
    const { proposal, target } = input;
    const content = target.fileContent;
    const targetRange = gate.targetRange;
    const targetLines = Math.max(0, targetRange.end - targetRange.start + 1);
    const uncovered = targetLines > 0 ? uncoveredWithin(targetRange, gate.deliveredRanges) : [];
    const uncoveredLines = uncovered.reduce((sum, r) => sum + (r.end - r.start + 1), 0);
    const highPriorityUnread = content ? uncovered.filter(r => rangeHasHighPriorityCode(content, r)) : [];

    if (content && targetLines > 0) {
        const coveredFraction = (targetLines - uncoveredLines) / targetLines;
        if (coveredFraction < INVESTIGATION_FLOOR_FRACTION && highPriorityUnread.length > 0) {
            const first = highPriorityUnread[0];
            reasons.push({
                code: 'investigation-floor',
                description: `Only ${Math.round(coveredFraction * 100)}% of lines ${formatRange(targetRange)} have been read, and unread security-relevant code remains (first: lines ${formatRange(first)}). Read more of the target before finishing.`,
            });
        }
    }

    if (canReject && highPriorityUnread.length > 0) {
        const range = highPriorityUnread[0];
        reasons.push({
            code: 'high-priority-unread-range',
            description: `Unread range lines ${range.start}-${range.end} contains security-relevant code (auth, exec, token, etc.)`,
        });
        coverageGaps.push({
            title: `Unread high-priority range: lines ${range.start}-${range.end} of ${target.filePath}`,
            detail: `This unread range contains security-relevant code (authentication, authorization, command execution, or token handling). Vulnerabilities in this range were not checked.`,
            file: target.filePath,
            line: range.start,
            lineEnd: range.end,
            requiredEvidence: [`Read lines ${range.start}-${range.end} and analyze for vulnerabilities`],
            suggestedNextAction: 'read_file',
            priority: 'high',
        });
    }

    if (!gate.openLeadsRejectedOnce) {
        const open = unresolvedOpenLeads(gate.currentLeads, proposal);
        for (const lead of open.slice(0, MAX_LISTED_OPEN_LEADS)) {
            reasons.push({
                code: 'open-leads',
                description: `Open lead not resolved: ${describeLead(lead)}`,
            });
        }
        if (open.length > MAX_LISTED_OPEN_LEADS) {
            reasons.push({ code: 'open-leads', description: `…and ${open.length - MAX_LISTED_OPEN_LEADS} more open lead(s)` });
        }
        if (open.length > 0) {
            reasons.push({
                code: 'open-leads',
                description: 'Resolve each open lead (status finding, note or dropped, with a resolution) or list it in coverageGaps. If you finish again with leads still open, they are recorded as coverage gaps.',
            });
        }
    }

    const totalLines = content ? content.split('\n').length : undefined;
    for (const finding of gate.findings ?? proposal.findings ?? []) {
        const line = typeof finding?.line === 'number' && Number.isFinite(finding.line) ? Math.floor(finding.line) : NaN;
        if (!Number.isFinite(line) || line < 1) continue;
        if (totalLines !== undefined && line > totalLines) continue;
        const rawEnd = typeof finding.lineEnd === 'number' && Number.isFinite(finding.lineEnd) && finding.lineEnd >= line
            ? Math.floor(finding.lineEnd)
            : line;
        const end = totalLines !== undefined ? Math.min(rawEnd, totalLines) : rawEnd;
        const unread = uncoveredWithin({ start: line, end }, gate.deliveredRanges);
        if (unread.length === 0) continue;
        const span = { start: unread[0].start, end: unread[unread.length - 1].end };
        reasons.push({
            code: 'finding-unread-lines',
            description: `read lines ${formatRange(span)} before reporting this finding (${finding.type} at line ${line})`,
        });
        coverageGaps.push({
            title: `Finding cites unread lines ${formatRange(span)}: ${finding.type} at line ${line}`,
            detail: `The finding was reported without lines ${formatRange(span)} being read.`,
            file: target.filePath,
            line: span.start,
            lineEnd: span.end,
            requiredEvidence: [`Read lines ${formatRange(span)} and confirm the finding`],
            suggestedNextAction: 'read_file',
            priority: 'medium',
        });
    }

    const AUTH_STORE_KEYWORDS = ['auth', 'guard', 'middleware', 'session', 'token', 'password', 'credential', 'db', 'database', 'store', 'model', 'repository', 'schema', 'query', 'prisma', 'sequelize', 'mongoose', 'knex', 'typeorm'];
    const isAuthOrStore = (reason: string, relation: string): boolean => {
        const low = `${reason} ${relation}`.toLowerCase();
        return AUTH_STORE_KEYWORDS.some(kw => low.includes(kw));
    };
    const secondRejectionAllowed = (gate.doneRuleRejections ?? 0) >= 1;
    const doneRuleReasons: FinishGateReason[] = [];
    const doneRuleGaps: FinishGateCoverageGap[] = [];

    if (gate.connectedFiles && gate.connectedFiles.length > 0) {
        for (const cf of gate.connectedFiles) {
            if (!isAuthOrStore(cf.reason, cf.relation)) continue;
            const normFile = normalizeGatePath(cf.file);
            const readOrGapped = input.investigation.wasFileRead(normFile)
                || (proposal.coverageGaps ?? []).some(g => (g.file && normalizeGatePath(g.file) === normFile) || normalizeGatePath(g.title).includes(normFile));
            if (!readOrGapped) {
                doneRuleReasons.push({
                    code: 'connected-file-unread',
                    description: `Connected file not read: ${cf.file} (${cf.relation}: ${cf.reason})`,
                });
                doneRuleGaps.push({
                    title: `Connected file not read: ${cf.file}`,
                    detail: `${cf.file} (${cf.relation}: ${cf.reason}) holds auth/data-store logic used by the target's routes but was not read or listed as a coverage gap.`,
                    file: cf.file,
                    requiredEvidence: [`Read ${cf.file} or list it as a coverage gap`],
                    suggestedNextAction: 'read_file',
                    priority: 'high',
                });
            }
        }
    }

    if (gate.gridCells && gate.gridCells.length > 0) {
        for (const cell of gate.gridCells) {
            if (cell.risk < 4) continue;
            if (cell.evidenceLines && cell.evidenceLines.length > 0) continue;
            doneRuleReasons.push({
                code: 'high-risk-cell-no-evidence',
                description: `Risk-${cell.risk} cell ${cell.id} (${cell.title}) has no evidence lines`,
            });
            doneRuleGaps.push({
                title: `No evidence lines for risk-${cell.risk} cell: ${cell.title}`,
                detail: `Grid cell ${cell.id} (${cell.attackType}, risk ${cell.risk}) has no evidence lines cited. Cite the specific lines that support the cell's status.`,
                file: target.filePath,
                requiredEvidence: [`Cite evidence lines for cell ${cell.id}`],
                suggestedNextAction: 'read_file',
                priority: 'high',
            });
        }
    }

    if (doneRuleReasons.length > 0) {
        if (secondRejectionAllowed) {
            coverageGaps.push(...doneRuleGaps);
        } else {
            reasons.push(...doneRuleReasons);
            coverageGaps.push(...doneRuleGaps);
        }
    }
}

function normalizeGatePath(p: string): string {
    return p.replace(/\\/g, '/').toLowerCase();
}

function countUnreviewedSensitiveHandlers(handlers: HandlerInventory, target: FinishGateInput['target']): number {
    if (!target.segment) return handlers.getUnreviewedSensitiveCount();
    const targetNorm = normalizeGatePath(target.filePath);
    const { startLine, endLine } = target.segment;
    return handlers.getAll().filter(h => {
        if (!h.securitySensitive || h.reviewed) return false;
        const handlerNorm = normalizeGatePath(h.filePath);
        if (handlerNorm !== targetNorm && !handlerNorm.endsWith(`/${targetNorm}`)) return true;
        return h.range.end >= startLine && h.range.start <= endLine;
    }).length;
}

export function evaluateFinishGate(input: FinishGateInput): FinishGateResult {
    const { proposal, state, evidence, workItems, handlers, candidates, investigation, scheduler, target, landing } = input;
    const evidenceGate = input.gateMode === 'evidence' ? input.evidenceGate : undefined;

    const reasons: FinishGateReason[] = [];
    const coverageGaps: FinishGateCoverageGap[] = [];
    const hasBudget = state.budget.stepsRemaining > 0 &&
                      state.budget.costSpentUsd < state.budget.costCapUsd;
    const hasWallClock = Date.now() - state.budget.startedAt < state.budget.wallClockMs;
    // Soft deadline: once 75% of the wall clock is spent, the gate stops
    // rejecting finishes. Unbounded checks (unread auth ranges, executable
    // work, scheduler actions) can never converge on a large auth-heavy
    // file, so a hard "reject while budget remains" rule grinds deep
    // investigators into a wall-clock discard. The last quarter of the
    // run is the landing window: finishes are accepted with their
    // un-investigated areas recorded as coverage gaps. The API's landing
    // mode (no more credits can be added, under three steps of budget
    // left) opens the same window early.
    const wallClockElapsedMs = Date.now() - state.budget.startedAt;
    const softDeadlinePassed = wallClockElapsedMs >= state.budget.wallClockMs * 0.75 || landing === true;

    // Evidence mode replaces the checklist checks (1, 2, 3b, 4, 5, 6) and
    // the unread-range check (7) with evidence checks; candidates (3) stay.
    const incompleteSteps = evidenceGate ? [] : investigation.getIncompleteSteps();

    // Check 1: Incomplete investigation steps
    if (incompleteSteps.length > 0) {
        for (const step of incompleteSteps) {
            reasons.push({
                code: 'incomplete-checklist',
                description: `Required investigation step not completed: ${step}`,
            });
            coverageGaps.push({
                title: `Investigation step not completed: ${step}`,
                detail: `The agent finished without completing this required investigation step: ${step}. This means the investigation was incomplete and vulnerabilities may have been missed.`,
                file: target.filePath,
                requiredEvidence: [`Complete the ${step} step before concluding no vulnerabilities exist`],
                suggestedNextAction: step === 'config-inspection' ? 'read_config'
                    : step === 'policy-check' ? 'check_policy'
                    : step === 'cross-file-flow' ? 'trace_flow_cross_file'
                    : step === 'auth-symbol-search' ? 'search_code'
                    : 'continue investigation',
                priority: 'high',
            });
        }
    }

    // Check 2: Unresolved architecture-risk tasks
    const unresolvedTasks = evidenceGate ? [] : investigation.getUnresolvedTasks();
    if (unresolvedTasks.length > 0) {
        for (const task of unresolvedTasks) {
            reasons.push({
                code: 'unresolved-task',
                description: `Architecture risk task unresolved: ${task.claim}`,
            });
            coverageGaps.push({
                title: `Architecture risk unresolved: ${task.claim}`,
                detail: `This architecture-risk investigation task was not resolved: ${task.claim}. Required evidence: ${task.requiredEvidence.join('; ')}.`,
                file: task.targetFiles[0] || target.filePath,
                requiredEvidence: task.requiredEvidence,
                suggestedNextAction: task.requiredTools[0] || 'continue investigation',
                priority: 'high',
            });
        }
    }

    // Check 3: Candidates not ready for the Juror block finish when budget
    // remains; when budget is exhausted they become coverage gaps. A
    // candidate is ready when its gate dimensions are satisfied, or when a
    // traced source-to-sink flow touches its location and no effective guard
    // was found. `verification` is never a pre-finish requirement: the
    // verifier runs after finish.
    //
    // Logic-class candidates (access control, mass assignment, privilege
    // escalation, etc.) do not require a traced taint flow: delivered read
    // coverage of the entry-point and vulnerable lines satisfies
    // `reachability`, and a claim stating actor+effect satisfies
    // `threat-model` and `impact`.
    if (!candidates.allReadyForJuror()) {
        const proposedFindings = proposal.findings ?? [];
        const steps = input.transcript ?? [];
        const hasTranscript = input.transcript !== undefined;
        const targetLang = target.language ?? target.filePath;
        const noStructure = !hasStructureSupport(targetLang);

        for (const candidate of candidates.getBlocking()) {
            const logicClass = isLogicClass(candidate.type);
            const flowRequired = !logicClass && FLOW_REQUIRED_TYPES.has(candidate.type.toLowerCase().replace(/[\s-]+/g, '_'));
            const treatAsReadOnly = logicClass || (flowRequired && noStructure);

            if (treatAsReadOnly) {
                const { entryDelivered, vulnDelivered } = candidateLinesDelivered(candidate, investigation, target.filePath, input.evidenceGate?.deliveredRanges);
                const matchedFinding = findMatchingFinding(candidate, proposedFindings);
                const claimSufficient = candidateClaimHasActorAndEffect(candidate)
                    || (matchedFinding !== undefined && findingTextHasActorAndEffect(matchedFinding));

                if (entryDelivered && vulnDelivered) {
                    const missingBefore = missingGateDimensions(candidate);
                    if (missingBefore.includes('reachability')) {
                        candidates.addEvidence(candidate.id, `logic-read-coverage:${candidate.locations[0]?.filePath}`, 'source', 'reachability');
                    }
                }
                if (claimSufficient) {
                    const missingBefore = missingGateDimensions(candidate);
                    if (missingBefore.includes('threat-model')) {
                        const src = matchedFinding ? `finding:${matchedFinding.line}` : candidate.id;
                        candidates.addEvidence(candidate.id, `logic-claim-threat:${src}`, 'policy', 'threat-model');
                    }
                    if (missingBefore.includes('impact')) {
                        const src = matchedFinding ? `finding:${matchedFinding.line}` : candidate.id;
                        candidates.addEvidence(candidate.id, `logic-claim-impact:${src}`, 'impact', 'impact');
                    }
                }

                if (missingGateDimensions(candidate).includes('control') && hasTranscript) {
                    if (checkGuardSatisfiesControl(candidate, steps)) {
                        candidates.addEvidence(candidate.id, `guard-control:${candidate.id}`, 'guard', 'control');
                    }
                }

                if (noStructure && flowRequired) {
                    const missingBefore = missingGateDimensions(candidate);
                    if (missingBefore.includes('control') && entryDelivered && vulnDelivered) {
                        candidates.addEvidence(candidate.id, `no-structure-read-control:${candidate.id}`, 'source', 'control');
                    }
                }
            }

            if (flowRequired && !noStructure && !candidate.flowTraced && steps.length > 0) {
                if (transcriptHasRuntimeEvidence(candidate, steps)) {
                    candidates.addEvidence(candidate.id, `runtime-test:${candidate.id}`, 'test', 'reachability');
                    candidate.flowTraced = true;
                }
            }

            if (candidates.isReadyForJuror(candidate.id)) continue;

            const missingDims = missingGateDimensions(candidate);
            const location = candidate.locations.map(l => `${l.filePath}:${l.line}`).join(', ') || target.filePath;

            if (flowRequired && !noStructure && !candidate.flowTraced && missingDims.includes('reachability') && hasTranscript) {
                if (!candidate.evidenceRefs.some(r => r.startsWith('coverage-gap:no-flow:'))) {
                    candidates.addEvidence(candidate.id, `coverage-gap:no-flow:${candidate.id}`, 'negative');
                    coverageGaps.push({
                        title: `No traced flow or runtime evidence for injection candidate`,
                        detail: `The taint tracker found no request-input sources for ${candidate.type} at ${location}. No run_tests observation confirmed the payload either. Recorded as a coverage gap.`,
                        file: candidate.locations[0]?.filePath || target.filePath,
                        line: candidate.locations[0]?.line,
                        requiredEvidence: [`Trace a source-to-sink flow or run a test that shows the payload reaching the sink`],
                        suggestedNextAction: 'trace_flow',
                        priority: 'medium',
                    });
                    continue;
                }
                continue;
            }

            let blocker: string;
            if (candidate.guardFound) {
                blocker = `an effective guard was found (${candidate.guardReason}) — show why it does not apply or drop the finding`;
            } else if (treatAsReadOnly) {
                const hints: string[] = [];
                if (missingDims.includes('reachability')) {
                    hints.push(`read the entry-point and vulnerable lines (${location}) so the read coverage proves reachability`);
                }
                if (missingDims.includes('threat-model') || missingDims.includes('impact')) {
                    hints.push('state which actor exploits the flaw and what effect it has (e.g. "unauthenticated user sets role to admin") in the candidate claim');
                }
                if (missingDims.includes('control') && !noStructure) {
                    hints.push(`run check_guard on the vulnerable location to satisfy the control dimension`);
                }
                blocker = hints.length > 0
                    ? hints.join('; ')
                    : `missing dimensions ${missingDims.join(', ')} — provide evidence for each`;
            } else {
                blocker = `no traced source-to-sink flow reaches ${location} — run trace_flow or trace_flow_cross_file on that file`;
            }

            const dimInfo = missingDims.length > 0
                ? ` (missing proof dimensions: ${missingDims.join(', ')}; ${blocker})`
                : ` (${candidate.evidenceRefs.length} evidence ref(s); ${blocker})`;
            reasons.push({
                code: 'non-terminal-candidate',
                description: `Candidate needs more evidence: ${candidate.claim} (status: ${candidate.status}${dimInfo})`,
            });
            coverageGaps.push({
                title: `Candidate needs more evidence: ${candidate.claim}`,
                detail: `This vulnerability candidate at ${location} has status "${candidate.status}" with ${candidate.evidenceRefs.length} evidence reference(s). Missing proof dimensions: ${missingDims.join(', ') || 'none'}. ${blocker[0].toUpperCase()}${blocker.slice(1)}.`,
                file: candidate.locations[0]?.filePath || target.filePath,
                requiredEvidence: candidate.requiredEvidence.map(e => `${e.description} (tools: ${(e.requiredTools || []).join(', ')})`),
                suggestedNextAction: treatAsReadOnly ? 'read_file' : (candidate.requiredEvidence[0]?.requiredTools || ['trace_flow_cross_file'])[0],
                priority: candidate.severity === 'high' || candidate.severity === 'critical' ? 'high' : 'medium',
            });
        }
    }

    // Check 3b: Unsatisfied evidence-ledger requirements
    const unsatisfiedReqs = evidenceGate ? [] : evidence.getUnsatisfiedRequirements();
    if (unsatisfiedReqs.length > 0) {
        for (const req of unsatisfiedReqs) {
            reasons.push({
                code: 'unsatisfied-evidence-requirement',
                description: `Evidence requirement not satisfied: ${req.description}`,
            });
            coverageGaps.push({
                title: `Evidence requirement not satisfied: ${req.description}`,
                detail: `The evidence ledger requirement "${req.description}" was not satisfied. Required tools: ${(req.requiredTools || []).join(', ')}. Accepted kinds: ${req.acceptedKinds.join(', ')}.`,
                file: req.targetFiles?.[0] || target.filePath,
                requiredEvidence: [req.description],
                suggestedNextAction: req.requiredTools?.[0] || 'continue investigation',
                priority: 'medium',
            });
        }
    }

    // Check 4: Unreviewed security-sensitive handlers
    const unreviewedSensitive = evidenceGate ? 0 : countUnreviewedSensitiveHandlers(handlers, target);
    if (unreviewedSensitive > 0) {
        reasons.push({
            code: 'unreviewed-handlers',
            description: `${unreviewedSensitive} security-sensitive handler(s) unreviewed`,
        });
    }

    // Check 5: Executable work items remain (only when budget is available)
    const executableWork = evidenceGate ? [] : workItems.getExecutable();
    if (executableWork.length > 0 && hasBudget && hasWallClock) {
        reasons.push({
            code: 'executable-work-remaining',
            description: `${executableWork.length} executable work item(s) remain`,
        });
    }

    // Check 6: Scheduler has a deterministic action (only when checklist incomplete)
    if (incompleteSteps.length > 0 && scheduler.kind === 'deterministic-action' && hasBudget && hasWallClock) {
        reasons.push({
            code: 'scheduler-has-action',
            description: `Scheduler has a deterministic action available: ${scheduler.reason}`,
        });
    }

    // Check 7: High-priority unread ranges — security-relevant code that
    // was never read. This prevents finishing while authentication,
    // authorization, or command-execution code remains uninspected.
    if (!evidenceGate && hasBudget && hasWallClock && target.fileContent) {
        const uncoveredRanges = investigation.getUncoveredRanges(target.filePath)
            .map(r => target.segment
                ? { start: Math.max(r.start, target.segment.startLine), end: Math.min(r.end, target.segment.endLine) }
                : r)
            .filter(r => r.start <= r.end);
        if (uncoveredRanges.length > 0) {
            for (const range of uncoveredRanges) {
                const hasHighPriority = rangeHasHighPriorityCode(target.fileContent, range);
                if (hasHighPriority) {
                    reasons.push({
                        code: 'high-priority-unread-range',
                        description: `Unread range lines ${range.start}-${range.end} contains security-relevant code (auth, exec, token, etc.)`,
                    });
                    coverageGaps.push({
                        title: `Unread high-priority range: lines ${range.start}-${range.end} of ${target.filePath}`,
                        detail: `This unread range contains security-relevant code (authentication, authorization, command execution, or token handling). Vulnerabilities in this range were not checked.`,
                        file: target.filePath,
                        requiredEvidence: [`Read lines ${range.start}-${range.end} and analyze for vulnerabilities`],
                        suggestedNextAction: 'read_file',
                        priority: 'high',
                    });
                    break;
                }
            }
        }
    }

    if (evidenceGate) {
        evaluateEvidenceChecks(input, evidenceGate, hasBudget && hasWallClock, reasons, coverageGaps);
    }

    const assuranceGate = input.assuranceGate;
    if (assuranceGate) {
        if (!assuranceGate.isFullyClosed) {
            for (const cell of assuranceGate.problems.open.slice(0, 10)) {
                reasons.push({
                    code: 'assurance-open-cell',
                    description: `Threat-grid cell still open: ${cell.id} [risk ${cell.risk}] ${cell.attackType}: ${cell.title}`,
                });
            }
            if (assuranceGate.problems.open.length > 10) {
                reasons.push({ code: 'assurance-open-cell', description: `…and ${assuranceGate.problems.open.length - 10} more open cell(s)` });
            }
        }
        for (const cell of assuranceGate.problems.weak.slice(0, 5)) {
            reasons.push({
                code: 'assurance-weak-cell',
                description: `Risk ${cell.risk} safe cell ${cell.id} needs traced or tested closure (currently ${cell.closure ?? 'none'}): ${cell.title}`,
            });
        }
    }

    // Decision:
    // - If no reasons → accept as complete
    // - If reasons exist but no budget/wall-clock, or the soft deadline
    //   (75% of the wall clock) has passed → accept as forced-incomplete
    // - If reasons exist and budget remains (and no soft deadline) → reject and continue

    if (reasons.length === 0) {
        return {
            accepted: true,
            mode: 'complete',
            reasons: [],
            normalizedFinish: proposal,
            ...(coverageGaps.length > 0 ? { coverageGaps } : {}),
        };
    }

    // Check if we can continue (budget + wall clock available, before the soft deadline)
    const canContinue = hasBudget && hasWallClock && !softDeadlinePassed && !isScanTerminal(state);

    if (!canContinue) {
        // Forced-incomplete: budget or wall clock exhausted
        return {
            accepted: true,
            mode: 'forced-incomplete',
            reasons,
            coverageGaps,
            normalizedFinish: proposal,
        };
    }

    // Reject finish — continue investigation
    const recoveryAction = !evidenceGate && scheduler.kind === 'deterministic-action' && scheduler.action
        ? scheduler.action
        : undefined;

    return {
        accepted: false,
        mode: 'continue',
        reasons,
        recoveryAction,
        coverageGaps,
    };
}

function isScanTerminal(state: ScanRunState): boolean {
    return state.phase === 'completed' || state.phase === 'terminated';
}
