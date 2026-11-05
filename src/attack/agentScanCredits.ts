import type { ApiClient } from '../api/client';
import {
    AGENT_SCAN_DEFAULTS,
    type AgentScanCapReason,
    type AgentScanCloseResponse,
    type AgentScanSettlement,
} from './agentScanProtocol';

export const AGENT_SCAN_BUDGET_EXHAUSTED_CODE = 'AGENT_SCAN_BUDGET_EXHAUSTED';

export const VERIFY_BUDGET_EXHAUSTED_REASON = 'Verification budget exhausted (top up credits to verify the remaining findings).';

export function isAgentScanBudgetExhausted(err: unknown): boolean {
    const code = (err as any)?.apiCode ?? (err as any)?.code;
    return code === AGENT_SCAN_BUDGET_EXHAUSTED_CODE;
}

export function capReasonSummary(capReason: AgentScanCapReason | undefined, maxCredits?: number): string | undefined {
    if (capReason === 'insufficient_credits') return 'This file needs more budget. Top up credits to scan deeper.';
    if (capReason === 'max_credits') return `Reached the ${maxCredits ?? AGENT_SCAN_DEFAULTS.maxCreditsPerRun}-credit maximum for one scan.`;
    return undefined;
}

export async function closeAgentScanRun(
    client: Pick<ApiClient, 'postJson'>,
    runId: string,
    status: string,
    terminationReason: string | undefined,
    signal?: AbortSignal,
): Promise<AgentScanSettlement | undefined> {
    try {
        const resp = await client.postJson<AgentScanCloseResponse>(
            '/agent/scan/close',
            { runId, status, terminationReason },
            signal,
        );
        const settlement = resp?.settlement;
        if (settlement && typeof settlement.creditsUsed === 'number') {
            return {
                creditsRefunded: typeof settlement.creditsRefunded === 'number' ? settlement.creditsRefunded : 0,
                creditsUsed: settlement.creditsUsed,
                ...(typeof settlement.costSpentUsd === 'number' ? { costSpentUsd: settlement.costSpentUsd } : {}),
            };
        }
    } catch { /* best-effort — janitor will expire the run */ }
    return undefined;
}

export class AgentScanRunCloser {
    private client?: Pick<ApiClient, 'postJson'>;
    private runId?: string;
    private status = 'failed';
    private terminationReason: string | undefined = 'api_error';
    private closing?: Promise<AgentScanSettlement | undefined>;

    attach(client: Pick<ApiClient, 'postJson'>, runId: string | undefined, status: string, terminationReason: string | undefined): void {
        if (!runId || this.closing) return;
        this.client = client;
        this.runId = runId;
        this.status = status;
        this.terminationReason = terminationReason;
    }

    close(): Promise<AgentScanSettlement | undefined> {
        if (!this.closing) {
            this.closing = this.client && this.runId
                ? closeAgentScanRun(this.client, this.runId, this.status, this.terminationReason)
                : Promise.resolve(undefined);
        }
        return this.closing;
    }
}

export interface CreditUsageFields {
    creditsUsed?: number;
    baseCredits?: number;
    creditExtensionsGranted?: number;
    creditsRefunded?: number;
}

export function formatCreditUsage(credits: CreditUsageFields): string | undefined {
    if (typeof credits.creditsUsed !== 'number') return undefined;
    const base = credits.baseCredits ?? AGENT_SCAN_DEFAULTS.creditsPerRun;
    const extensions = credits.creditExtensionsGranted ?? 0;
    let text = extensions > 0 && credits.creditsUsed >= base
        ? `This scan used ${credits.creditsUsed} credits (${base} + ${extensions} extension${extensions === 1 ? '' : 's'}).`
        : `This scan used ${credits.creditsUsed} credit${credits.creditsUsed === 1 ? '' : 's'}.`;
    if (credits.creditsRefunded && credits.creditsRefunded > 0) {
        text += ` ${credits.creditsRefunded} credit${credits.creditsRefunded === 1 ? ' was' : 's were'} refunded.`;
    }
    return text;
}
