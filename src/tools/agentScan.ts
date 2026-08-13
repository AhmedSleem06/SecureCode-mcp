/**
 * securecode.agent-scan MCP tool — agent-mode scan.
 *
 * An AI investigator that reads files, traces data flows, checks guards,
 * and compares endpoint policies to find vulnerabilities. Slower but deeper
 * than a deep scan. The agent replaces the Scout; its findings are verified
 * by the existing Juror + Phase 3 pipeline.
 *
 * Flow:
 *   1. Resolve code + language from filePath
 *   2. Build endpoint context from the project map
 *   3. Run the agent loop (POST /agent/scan/start + /step loop)
 *   4. Map agent findings → CandidateContext[]
 *   5. POST /scan with scanDepth: 'agent' + candidateContexts (skips Scout,
 *      Juror + Phase 3 verify the agent's candidates)
 *   6. Return merged result (agent findings + Juror-verified findings)
 */

import { ApiClient } from '../api/client';
import type { ServerContext } from '../mcp/types';
import { readFileFromWorkspace } from '../utils/files';
import { getEndpointContextForFile } from '../project-map/mapContext';
import { runAgentScan } from '../attack/agentScanLoop';
import type { AgentScanFinding, AgentScanTarget } from '../attack/agentScanProtocol';
import type { ScanResponse } from '../api/types';

interface CandidateContext {
    line: number;
    lineEnd?: number;
    type: string;
    snippet?: string;
    definitionContext?: string;
}

function mapFindingsToCandidates(findings: AgentScanFinding[]): CandidateContext[] {
    return findings.map(f => ({
        line: f.line,
        lineEnd: f.lineEnd,
        type: f.type,
        snippet: f.evidence,
        definitionContext: f.why,
    }));
}

export async function toolAgentScan(ctx: ServerContext, args: any): Promise<unknown> {
    const progress = args._progress as ((progress: number, total: number, message: string) => void) | undefined;

    // 1. Resolve code + language
    let code: string;
    let language: string;
    let filePath: string | undefined;

    if (args.filePath) {
        filePath = args.filePath;
        const fileResult = readFileFromWorkspace(ctx.workspaceRoot, args.filePath);
        code = fileResult.code;
        language = args.language || fileResult.language;
    } else if (args.code) {
        code = args.code;
        language = args.language || 'javascript';
    } else {
        throw new Error('Either filePath or code must be provided.');
    }

    // 2. Build endpoint context from the project map
    let endpointContext: any[] = [];
    if (filePath) {
        try {
            endpointContext = await getEndpointContextForFile(filePath, ctx.workspaceRoot);
        } catch {
            // best-effort — proceed without endpoint context
        }
    }

    // 3. Run the agent loop
    const target: AgentScanTarget = {
        filePath: filePath || 'inline-code',
        language,
        fileContent: code,
        endpointContext,
    };

    const agentResult = await runAgentScan(ctx, target, {
        onProgress: (steps, max, msg) => {
            if (progress) progress(steps, max, msg);
        },
    });

    if (agentResult.status === 'spawn_failed') {
        throw new Error(agentResult.error || 'Agent scan failed to start.');
    }

    // 4. Map agent findings → CandidateContext[]
    const candidateContexts = mapFindingsToCandidates(agentResult.findings);

    // 5. If no findings, return early
    if (candidateContexts.length === 0) {
        return {
            status: agentResult.status,
            summary: agentResult.summary || 'Agent completed with no findings.',
            findings: [],
            agentFindings: agentResult.findings,
            stepsUsed: agentResult.stepsUsed,
            costSpentUsd: agentResult.costSpentUsd,
            transcript: agentResult.transcript,
        };
    }

    // 6. POST /scan with scanDepth: 'agent' + candidateContexts
    //    This skips Scout and sends the agent's candidates directly to Juror
    //    + Phase 3 for verification.
    const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken });
    const scanResp = await client.postJson<ScanResponse>('/scan', {
        code,
        language,
        ...(filePath ? { filePath } : {}),
        scanDepth: 'agent',
        candidateContexts,
        ...(endpointContext.length > 0 ? { endpointContext } : {}),
    });

    // 7. Return merged result
    return {
        status: agentResult.status,
        summary: agentResult.summary,
        agentFindings: agentResult.findings,
        verifiedFindings: scanResp.finalFindings || [],
        allFindings: scanResp.findings || [],
        scanId: scanResp.scanId,
        scanType: scanResp.scanType,
        degraded: scanResp.degraded,
        scanCredits: scanResp.scanCredits,
        plan: scanResp.plan,
        stepsUsed: agentResult.stepsUsed,
        costSpentUsd: agentResult.costSpentUsd,
        transcript: agentResult.transcript,
    };
}
