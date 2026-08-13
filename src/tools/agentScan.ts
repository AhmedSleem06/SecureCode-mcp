/**
 * securecode.agent-scan MCP tool — agent-mode scan with exploit proof.
 *
 * An AI investigator that reads files, traces data flows, checks guards,
 * and compares endpoint policies to find vulnerabilities. Each high/critical
 * finding is then sent to the sandbox for PROVEN/UNPROVEN verification before
 * the Juror confirms it.
 *
 * Flow:
 *   1. Resolve code + language from filePath
 *   2. Build endpoint context from the project map
 *   3. Run the agent loop (POST /agent/scan/start + /step loop)
 *   4. For each high/critical finding → POST /sandbox/prove → PROVEN/UNPROVEN
 *   5. Map agent findings → CandidateContext[]
 *   6. POST /scan with scanDepth: 'agent' + candidateContexts (skips Scout,
 *      Juror + Phase 3 verify the agent's candidates)
 *   7. Return merged result (agent findings + proven stamps + Juror-verified)
 */

import { ApiClient } from '../api/client';
import type { ServerContext } from '../mcp/types';
import { readFileFromWorkspace } from '../utils/files';
import { getEndpointContextForFile } from '../project-map/mapContext';
import { runAgentScan } from '../attack/agentScanLoop';
import type { AgentScanFinding, AgentScanTarget } from '../attack/agentScanProtocol';
import type { ScanResponse, SandboxProveResponse } from '../api/types';

interface CandidateContext {
    line: number;
    lineEnd?: number;
    type: string;
    snippet?: string;
    definitionContext?: string;
}

interface ProvenFinding extends AgentScanFinding {
    proven: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'NOT_REPRODUCIBLE' | 'SKIPPED';
    provenReason?: string;
}

function mapFindingsToCandidates(findings: ProvenFinding[]): CandidateContext[] {
    return findings.map(f => ({
        line: f.line,
        lineEnd: f.lineEnd,
        type: f.type,
        snippet: f.evidence,
        definitionContext: f.why,
    }));
}

/** Only prove high/critical findings — don't waste credits on low/medium. */
function shouldProve(finding: AgentScanFinding): boolean {
    return finding.severity === 'critical' || finding.severity === 'high';
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

    // 4. Prove each high/critical finding via the sandbox
    const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken });
    const provenFindings: ProvenFinding[] = [];

    const proveable = agentResult.findings.filter(shouldProve);
    if (proveable.length > 0 && progress) {
        progress(0, proveable.length, `Proving ${proveable.length} finding(s) in sandbox...`);
    }

    let proveIdx = 0;
    for (const finding of agentResult.findings) {
        if (!shouldProve(finding)) {
            provenFindings.push({ ...finding, proven: 'SKIPPED', provenReason: 'Low/medium severity — not proven' });
            continue;
        }

        try {
            if (progress) {
                proveIdx++;
                progress(proveIdx, proveable.length, `Proving ${finding.type} at line ${finding.line}...`);
            }

            const proveResp = await client.postJson<SandboxProveResponse>('/sandbox/prove', {
                code,
                language,
                vulnerabilityType: finding.type,
                line: finding.line,
                lineEnd: finding.lineEnd,
                evidence: finding.evidence,
                why: finding.why,
            });

            provenFindings.push({
                ...finding,
                proven: proveResp.proven,
                provenReason: proveResp.rationale || proveResp.skipReason || proveResp.sandbox?.reason,
            });
        } catch (err: any) {
            // Insufficient credits or API error — skip proving, mark as INCONCLUSIVE
            provenFindings.push({
                ...finding,
                proven: 'INCONCLUSIVE',
                provenReason: `Sandbox prove failed: ${err.message || err}`,
            });
        }
    }

    // 5. Map findings → CandidateContext[]
    const candidateContexts = mapFindingsToCandidates(provenFindings);

    // 6. If no findings, return early
    if (candidateContexts.length === 0) {
        return {
            status: agentResult.status,
            summary: agentResult.summary || 'Agent completed with no findings.',
            findings: [],
            agentFindings: provenFindings,
            stepsUsed: agentResult.stepsUsed,
            costSpentUsd: agentResult.costSpentUsd,
            transcript: agentResult.transcript,
        };
    }

    // 7. POST /scan with scanDepth: 'agent' + candidateContexts
    //    This skips Scout and sends the agent's candidates directly to Juror
    //    + Phase 3 for verification.
    const scanResp = await client.postJson<ScanResponse>('/scan', {
        code,
        language,
        ...(filePath ? { filePath } : {}),
        scanDepth: 'agent',
        candidateContexts,
        ...(endpointContext.length > 0 ? { endpointContext } : {}),
    });

    // 8. Return merged result with proven stamps
    return {
        status: agentResult.status,
        summary: agentResult.summary,
        agentFindings: provenFindings,
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
        provenCount: provenFindings.filter(f => f.proven === 'PROVEN').length,
        unprovenCount: provenFindings.filter(f => f.proven === 'UNPROVEN').length,
        inconclusiveCount: provenFindings.filter(f => f.proven === 'INCONCLUSIVE').length,
    };
}
