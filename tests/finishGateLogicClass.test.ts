import { describe, it, expect } from 'vitest';
import { evaluateFinishGate, LOGIC_BUG_TYPES } from '../src/attack/finishGate';
import { createScanRunState } from '../src/attack/scanState';
import { EvidenceLedger } from '../src/attack/evidenceLedger';
import { WorkItemQueue } from '../src/attack/workItem';
import { HandlerInventory } from '../src/project-map/handlerInventory';
import { CandidateStore } from '../src/attack/candidateStore';
import { InvestigationState } from '../src/attack/investigationState';

const budget = { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 };
const target = { filePath: 'src/users.ts', language: 'typescript', fileContent: 'export function handler() {}' };
const finishProposal: any = { type: 'finish', findings: [], summary: 'done', selfCritique: 'checked' };

function makeInput(overrides?: Partial<any>) {
    const state = createScanRunState('run-1', target, budget);
    return {
        proposal: finishProposal,
        state,
        evidence: new EvidenceLedger(),
        workItems: new WorkItemQueue(),
        handlers: new HandlerInventory(),
        candidates: new CandidateStore(),
        investigation: new InvestigationState(),
        scheduler: { kind: 'finish-ready' as const, reason: 'no work' },
        target: { filePath: 'src/users.ts' },
        gateMode: 'evidence' as const,
        evidenceGate: {
            currentLeads: [],
            deliveredRanges: [{ start: 1, end: 120 }],
            targetRange: { start: 1, end: 120 },
            openLeadsRejectedOnce: true,
        },
        ...overrides,
    };
}

describe('Finish Gate — logic-class candidate evidence rules', () => {

    it('logic-class candidate with read coverage passes (reachability satisfied by read lines)', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordRead('src/users.ts', 1, 120, 120);
        investigation.recordActualRead('src/users.ts', 1, 120, 120, false);

        const id = candidates.register({
            rootCauseId: 'mass-assign-role',
            type: 'mass_assignment',
            severity: 'high',
            locations: [{ filePath: 'src/users.ts', line: 80 }],
            claim: 'Authenticated user sets body.role="admin" via PUT /users/me, bypassing requireAdmin — privilege escalation',
        });
        candidates.addEvidence(id, 'backfill:source:src/users.ts', 'source', 'source');
        candidates.addEvidence(id, 'backfill:check_guard:src/users.ts', 'guard', 'control');

        const input = makeInput({ candidates, investigation });
        const result = evaluateFinishGate(input);
        const candidateReasons = result.reasons.filter(r => r.code === 'non-terminal-candidate');
        expect(candidateReasons).toHaveLength(0);
    });

    it('logic-class candidate with UNREAD lines is still rejected', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();

        const id = candidates.register({
            rootCauseId: 'mass-assign-role',
            type: 'broken_access_control',
            severity: 'high',
            locations: [{ filePath: 'src/users.ts', line: 80 }],
            claim: 'Authenticated user sets body.role="admin" via PUT /users/me — privilege escalation',
        });
        candidates.addEvidence(id, 'backfill:source:src/users.ts', 'source', 'source');
        candidates.addEvidence(id, 'backfill:check_guard:src/users.ts', 'guard', 'control');

        const input = makeInput({ candidates, investigation });
        input.evidenceGate = { ...input.evidenceGate, deliveredRanges: [] };
        const result = evaluateFinishGate(input);
        const candidateReasons = result.reasons.filter(r => r.code === 'non-terminal-candidate');
        expect(candidateReasons.length).toBeGreaterThan(0);
        expect(candidateReasons[0].description).toContain('read the entry-point');
    });

    it('injection candidate still requires traced flow even with read coverage', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordRead('src/users.ts', 1, 120, 120);
        investigation.recordActualRead('src/users.ts', 1, 120, 120, false);

        const id = candidates.register({
            rootCauseId: 'sqli-1',
            type: 'sql_injection',
            severity: 'high',
            locations: [{ filePath: 'src/users.ts', line: 50 }],
            claim: 'Attacker injects SQL via user input into query at line 50',
        });
        candidates.addEvidence(id, 'backfill:source:src/users.ts', 'source', 'source');
        candidates.addEvidence(id, 'backfill:check_guard:src/users.ts', 'guard', 'control');

        const input = makeInput({ candidates, investigation });
        const result = evaluateFinishGate(input);
        const candidateReasons = result.reasons.filter(r => r.code === 'non-terminal-candidate');
        expect(candidateReasons.length).toBeGreaterThan(0);
        expect(candidateReasons[0].description).toContain('trace_flow');
    });

    it('logic-class message is specific: tells agent what to read or how to describe the attack', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordRead('src/users.ts', 1, 120, 120);
        investigation.recordActualRead('src/users.ts', 1, 120, 120, false);

        const id = candidates.register({
            rootCauseId: 'priv-esc-1',
            type: 'privilege_escalation',
            severity: 'high',
            locations: [{ filePath: 'src/users.ts', line: 80 }],
            claim: 'Role field is writable',
        });
        candidates.addEvidence(id, 'backfill:source:src/users.ts', 'source', 'source');
        candidates.addEvidence(id, 'backfill:check_guard:src/users.ts', 'guard', 'control');

        const input = makeInput({ candidates, investigation });
        const result = evaluateFinishGate(input);
        const candidateReasons = result.reasons.filter(r => r.code === 'non-terminal-candidate');
        expect(candidateReasons.length).toBeGreaterThan(0);
        expect(candidateReasons[0].description).toContain('state which actor');
        expect(candidateReasons[0].description).not.toContain('trace_flow');
    });

    it('claim with actor and effect auto-satisfies threat-model and impact', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordRead('src/users.ts', 1, 120, 120);
        investigation.recordActualRead('src/users.ts', 1, 120, 120, false);

        const id = candidates.register({
            rootCauseId: 'idor-1',
            type: 'idor',
            severity: 'high',
            locations: [{ filePath: 'src/users.ts', line: 42 }],
            claim: 'Any authenticated user can access and modify another user\'s profile by changing the userId parameter',
        });
        candidates.addEvidence(id, 'backfill:source:src/users.ts', 'source', 'source');
        candidates.addEvidence(id, 'backfill:check_guard:src/users.ts', 'guard', 'control');

        const input = makeInput({ candidates, investigation });
        const result = evaluateFinishGate(input);
        const candidateReasons = result.reasons.filter(r => r.code === 'non-terminal-candidate');
        expect(candidateReasons).toHaveLength(0);
    });

    it.each([
        ['hardcoded_secret', 7, 'If the env var is missing, anyone can forge a token signed with the public fallback key and get past requireAdmin'],
        ['denial_of_service', 38, 'An unauthenticated caller can send a long dotted email that hangs the regex and blocks the event loop'],
        ['user_enumeration', 41, 'An anonymous caller can find out which emails are registered from the 409 response'],
    ])('non-injection class %s is closed by read lines + actor/effect claim', (type, line, claim) => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordRead('src/users.ts', 1, 120, 120);
        investigation.recordActualRead('src/users.ts', 1, 120, 120, false);
        const id = candidates.register({ rootCauseId: `rc-${type}`, type, severity: 'medium', locations: [{ filePath: 'src/users.ts', line }], claim });
        candidates.addEvidence(id, 'backfill:source:src/users.ts', 'source', 'source');
        candidates.addEvidence(id, 'backfill:check_guard:src/users.ts', 'guard', 'control');
        const result = evaluateFinishGate(makeInput({ candidates, investigation }));
        expect(result.reasons.filter(r => r.code === 'non-terminal-candidate')).toHaveLength(0);
    });

    it('lines shown to the model in the prompt count as read for the target file', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        const id = candidates.register({
            rootCauseId: 'mass-assign-role',
            type: 'mass_assignment',
            severity: 'high',
            locations: [{ filePath: 'src/users.ts', line: 80 }],
            claim: 'Any member sets body.role="admin" via PUT /users/me and bypasses requireAdmin',
        });
        candidates.addEvidence(id, 'backfill:source:src/users.ts', 'source', 'source');
        candidates.addEvidence(id, 'backfill:check_guard:src/users.ts', 'guard', 'control');
        const shown = evaluateFinishGate(makeInput({ candidates, investigation }));
        expect(shown.reasons.filter(r => r.code === 'non-terminal-candidate')).toHaveLength(0);
    });

    it('a prompt range that does not include the cited line does not count', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        const id = candidates.register({
            rootCauseId: 'mass-assign-role',
            type: 'mass_assignment',
            severity: 'high',
            locations: [{ filePath: 'src/users.ts', line: 80 }],
            claim: 'Any member sets body.role="admin" via PUT /users/me and bypasses requireAdmin',
        });
        candidates.addEvidence(id, 'backfill:source:src/users.ts', 'source', 'source');
        candidates.addEvidence(id, 'backfill:check_guard:src/users.ts', 'guard', 'control');
        const input = makeInput({ candidates, investigation });
        input.evidenceGate = { ...input.evidenceGate, deliveredRanges: [{ start: 1, end: 60 }] };
        const result = evaluateFinishGate(input);
        expect(result.reasons.filter(r => r.code === 'non-terminal-candidate').length).toBeGreaterThan(0);
    });

    it('LOGIC_BUG_TYPES covers the documented set', () => {
        expect(LOGIC_BUG_TYPES.has('broken_access_control')).toBe(true);
        expect(LOGIC_BUG_TYPES.has('mass_assignment')).toBe(true);
        expect(LOGIC_BUG_TYPES.has('privilege_escalation')).toBe(true);
        expect(LOGIC_BUG_TYPES.has('race_condition')).toBe(true);
        expect(LOGIC_BUG_TYPES.has('auth_bypass')).toBe(true);
        expect(LOGIC_BUG_TYPES.has('idor')).toBe(true);
        expect(LOGIC_BUG_TYPES.has('business_logic')).toBe(true);
        expect(LOGIC_BUG_TYPES.has('missing_authorization')).toBe(true);
        expect(LOGIC_BUG_TYPES.has('insecure_default')).toBe(true);
        expect(LOGIC_BUG_TYPES.has('config_default')).toBe(true);
        expect(LOGIC_BUG_TYPES.has('sql_injection')).toBe(false);
        expect(LOGIC_BUG_TYPES.has('xss')).toBe(false);
    });

    it('handles type names with hyphens and spaces (broken-access-control)', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordRead('src/users.ts', 1, 120, 120);
        investigation.recordActualRead('src/users.ts', 1, 120, 120, false);

        const id = candidates.register({
            rootCauseId: 'bac-1',
            type: 'Broken Access Control',
            severity: 'high',
            locations: [{ filePath: 'src/users.ts', line: 80 }],
            claim: 'Attacker bypasses admin guard to escalate privilege',
        });
        candidates.addEvidence(id, 'backfill:source:src/users.ts', 'source', 'source');
        candidates.addEvidence(id, 'backfill:check_guard:src/users.ts', 'guard', 'control');

        const input = makeInput({ candidates, investigation });
        const result = evaluateFinishGate(input);
        const candidateReasons = result.reasons.filter(r => r.code === 'non-terminal-candidate');
        expect(candidateReasons).toHaveLength(0);
    });
});
