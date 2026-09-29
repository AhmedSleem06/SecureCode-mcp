/**
 * Deterministic finding corroboration — port of api/src/attacker/agentCorroboration.ts.
 *
 * assembleAgentFindings maps a finish action's findings onto the transcript and
 * stamps each one via the full deterministic probe rules (probeRules.ts): a
 * finding is only 'confirmed' when its cited step's observation satisfies the
 * action's declared expect. corroborateStep keeps the API's per-step seam but
 * is strengthened from the API's minimal rule-0 check to the full rule set.
 */

import type { AgentFinding, AgentHttpRequestAction, AgentObservation, AgentTranscriptStep } from './protocol';
import { applyProbeRules, type ProbeRuleRequest, type ProbeRuleResponse, type ProbeRuleResult } from './probeRules';
import { SUSPECTED_FINDING_REASON, type ReportedAgentFinding } from './report';

const REFUTED_NOTE = 'Probe rules refuted the cited step — needs review';

function toRuleRequest(action: AgentHttpRequestAction): ProbeRuleRequest {
    return {
        method: action.method,
        path: action.path,
        headers: action.headers,
        body: action.body,
        successStatus: action.expect?.successStatus,
        successBodyPattern: action.expect?.successBodyPattern,
        successHeaders: action.expect?.successHeaders,
        successLatencyMs: action.expect?.successLatencyMs,
        successConfirmedBy: action.expect?.successConfirmedBy,
        successEvidenceNeeded: action.expect?.successEvidenceNeeded,
        expectedStatus: action.expect?.expectedStatus,
        authRequired: action.expect?.authRequired,
        authEnvVars: action.expect?.authEnvVars,
    };
}

function toRuleResponse(observation: AgentObservation): ProbeRuleResponse {
    return {
        statusCode: observation.statusCode,
        headers: observation.headers,
        body: observation.body,
        latencyMs: observation.latencyMs,
    };
}

export function corroborateStep(
    attackReq: ProbeRuleRequest,
    attackResp: ProbeRuleResponse | null,
    baselineReq: ProbeRuleRequest | null = null,
    baselineResp: ProbeRuleResponse | null = null,
): ProbeRuleResult {
    return applyProbeRules(attackReq, attackResp, baselineReq, baselineResp);
}

function baselinePair(
    evidenceStepIndex: number,
    transcript: AgentTranscriptStep[],
): { req: ProbeRuleRequest; resp: ProbeRuleResponse | null } | null {
    if (evidenceStepIndex <= 0) return null;
    const first = transcript[0];
    if (!first) return null;
    return {
        req: toRuleRequest(first.action),
        resp: first.observation.error ? null : toRuleResponse(first.observation),
    };
}

export function assembleAgentFindings(
    findings: AgentFinding[],
    transcript: AgentTranscriptStep[],
): ReportedAgentFinding[] {
    return findings.map((finding) => {
        const step = transcript[finding.evidenceStepIndex];
        if (!step) {
            return {
                ...finding,
                confirmation: 'suspected' as const,
                reason: `Evidence step ${finding.evidenceStepIndex} missing`,
            };
        }
        if (!step.action.expect) {
            return {
                ...finding,
                confirmation: 'suspected' as const,
                reason: SUSPECTED_FINDING_REASON,
            };
        }
        const baseline = baselinePair(finding.evidenceStepIndex, transcript);
        const result = corroborateStep(
            toRuleRequest(step.action),
            step.observation.error ? null : toRuleResponse(step.observation),
            baseline?.req ?? null,
            baseline?.resp ?? null,
        );
        if (result.verdict === 'confirmed-bypass') {
            return {
                ...finding,
                confirmation: 'confirmed' as const,
                rule: result.rule,
                reason: result.reason,
            };
        }
        if (result.verdict === 'refuted') {
            return {
                ...finding,
                confirmation: 'suspected' as const,
                rule: result.rule,
                reason: REFUTED_NOTE,
            };
        }
        return {
            ...finding,
            confirmation: 'suspected' as const,
            reason: SUSPECTED_FINDING_REASON,
        };
    });
}
