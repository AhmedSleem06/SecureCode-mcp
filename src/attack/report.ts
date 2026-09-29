import type { AgentTranscriptStep, AgentFinding, AgentRunStatus } from './protocol';

export interface ReportedAgentFinding extends AgentFinding {
    confirmation: 'confirmed' | 'suspected';
    rule?: string;
    reason?: string;
}

export type ReportableAgentFinding = AgentFinding & Partial<Pick<ReportedAgentFinding, 'confirmation' | 'rule' | 'reason'>>;

export const SUSPECTED_FINDING_REASON = 'Agent-reported finding (deterministic verification not yet implemented)';

export interface AttackReport {
    status: AgentRunStatus;
    findings: ReportedAgentFinding[];
    transcript: AgentTranscriptStep[];
    summary?: string;
    stepsUsed: number;
    costSpentUsd: number;
}

const JWT_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
const API_KEY_RE = /\b[A-Za-z0-9]{32,}\b/g;
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const BEARER_RE = /Bearer\s+[A-Za-z0-9._-]+/gi;

export function redactText(text: string): string {
    return text
        .replace(BEARER_RE, 'Bearer [REDACTED]')
        .replace(JWT_RE, '[JWT_REDACTED]')
        .replace(EMAIL_RE, '[EMAIL_REDACTED]')
        .replace(API_KEY_RE, (match) => (match.length === 32 || match.length === 40 || match.length === 64 ? '[REDACTED]' : match));
}

export function buildReport(
    status: AgentRunStatus,
    findings: ReportableAgentFinding[],
    transcript: AgentTranscriptStep[],
    stepsUsed: number,
    costSpentUsd: number,
    summary?: string,
): AttackReport {
    return {
        status,
        findings: findings.map((f) => ({
            ...f,
            confirmation: f.confirmation ?? ('suspected' as const),
            reason: f.reason ?? SUSPECTED_FINDING_REASON,
        })),
        transcript: transcript.map((step) => ({
            action: {
                ...step.action,
                headers: redactHeaders(step.action.headers),
            },
            observation: {
                ...step.observation,
                headers: redactHeaders(step.observation.headers),
                body: redactText(step.observation.body),
            },
        })),
        summary,
        stepsUsed,
        costSpentUsd,
    };
}

function redactHeaders(headers?: Record<string, string>): Record<string, string> {
    if (!headers) return {};
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
        if (/authorization|cookie|x-api-key|api-key/i.test(k)) {
            out[k] = '[REDACTED]';
        } else {
            out[k] = v;
        }
    }
    return out;
}
