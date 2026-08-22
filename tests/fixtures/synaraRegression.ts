/**
 * Synara regression fixtures — capture the exact findings the old Agent Scan
 * produced against the Synara project, the expected precision-classified
 * output, and the evidence requirements for each case.
 *
 * These fixtures are the acceptance criteria for the precision-first
 * improvement plan. The scanner must NOT reproduce the old over-classified
 * findings after the improvements are deployed.
 *
 * Old scan: 2026-08-22, 3 files, 3 PROVEN findings (all rejected by manual
 * review as overstated). The underlying behavior was real; the vulnerability
 * classification was not established for any of the three.
 */

// ── Old scan result (what the scanner produced) ─────────────────────────────

export interface OldScanFinding {
    file: string;
    line: number;
    lineEnd?: number;
    type: string;
    severity: string;
    confidence: number;
    oldProven: string;
    oldEvidenceLevel: string;
    evidence: string;
    why: string;
}

export const OLD_SCAN_RESULTS: OldScanFinding[] = [
    {
        file: 'apps/server/src/http.ts',
        line: 310,
        lineEnd: 319,
        type: 'broken_access_control',
        severity: 'high',
        confidence: 80,
        oldProven: 'PROVEN',
        oldEvidenceLevel: 'policy-checked+verified',
        evidence:
            'isLegacyTokenAuthorized() returns true (bypassing authentication) when: (1) config.host is loopback, (2) no publicUrl is set, AND (3) authToken is empty/falsy OR the request\'s ?token= query param matches authToken.',
        why:
            'On loopback deployments without publicUrl, if authToken is not set, all 6 GET endpoints and the binary upload handler accept any request without authentication.',
    },
    {
        file: 'apps/server/src/http.ts',
        line: 848,
        lineEnd: 850,
        type: 'broken_access_control',
        severity: 'high',
        confidence: 80,
        oldProven: 'PROVEN',
        oldEvidenceLevel: 'policy-checked+verified',
        evidence:
            'In binaryUploadEffectHandler, when isLegacyTokenAuthorized returns true, the attachment principal is set to LOCAL_LOOPBACK_ATTACHMENT_PRINCIPAL instead of being derived from an authenticated session.',
        why:
            'The LOCAL_LOOPBACK_ATTACHMENT_PRINCIPAL is a shared principal that doesn\'t scope uploaded files to a specific user session.',
    },
    {
        file: 'apps/server/src/wsRpc.ts',
        line: 2042,
        lineEnd: 2050,
        type: 'broken_access_control',
        severity: 'high',
        confidence: 85,
        oldProven: 'PROVEN',
        oldEvidenceLevel: 'taint-traced+policy-checked+verified',
        evidence:
            'authenticateRpcWebSocketUpgrade bypasses full ServerAuth when isLoopbackHost(config.host) && !config.publicUrl && input.legacyToken === input.config.authToken, returning Effect.succeed(null) which grants an unauthenticated \'owner\' role session.',
        why:
            'Any local process that knows or guesses the authToken can establish a WebSocket connection with full owner privileges including shell command execution, file operations, and external MCP management.',
    },
];

// ── Expected precision-classified output ────────────────────────────────────

export type ExpectedClassification =
    | 'finding'
    | 'investigationNote'
    | 'coverageGap'
    | 'not-reported';

export type ExpectedVerificationLevel =
    | 'logic-confirmed'
    | 'path-confirmed'
    | 'impact-confirmed'
    | 'exploit-confirmed';

export interface ExpectedRegressionOutcome {
    file: string;
    line: number;
    oldFinding: OldScanFinding;

    /**
     * What the old scan classified as a PROVEN high-severity finding.
     * After improvements, this should NOT be a high-severity finding
     * unless the full evidence chain is established.
     */
    expectedClassification: ExpectedClassification;

    /**
     * The verification level the old scan claimed vs. what it actually
     * demonstrated.
     */
    oldClaimedLevel: ExpectedVerificationLevel;
    actualDemonstratedLevel: ExpectedVerificationLevel;

    /**
     * Evidence the old scan was missing. The improved scanner must
     * collect this evidence before classifying as a finding.
     */
    missingEvidence: string[];

    /**
     * Root cause — if two findings share a root cause, they should be
     * correlated, not reported as independent findings.
     */
    rootCauseId: string;

    /**
     * Whether the threat model was established.
     */
    threatModelEstablished: boolean;

    /**
     * Human-review verdict from the manual review.
     */
    reviewVerdict:
        | 'confirmed-vulnerability'
        | 'design-risk'
        | 'investigation-note'
        | 'overstated'
        | 'false-positive';
    reviewNotes: string;
}

export const EXPECTED_OUTCOMES: ExpectedRegressionOutcome[] = [
    {
        file: 'apps/server/src/http.ts',
        line: 310,
        oldFinding: OLD_SCAN_RESULTS[0],
        expectedClassification: 'investigationNote',
        oldClaimedLevel: 'impact-confirmed',
        actualDemonstratedLevel: 'logic-confirmed',
        missingEvidence: [
            'Inspect config.ts remoteAccessPolicyError to determine whether empty-authToken loopback is a supported configuration',
            'Inspect main.ts startup validation to determine default host and token requirements',
            'Establish whether the product treats untrusted local processes as an attacker model',
            'Determine whether the empty-authToken state is reachable in a supported deployment path',
            'Verify query-token exposure in logs/referer is a real risk vs. a design tradeoff',
        ],
        rootCauseId: 'loopback-legacy-token-auth-bypass',
        threatModelEstablished: false,
        reviewVerdict: 'design-risk',
        reviewNotes:
            'The authentication bypass branch is real. The product intentionally supports loopback legacy tokens for desktop compatibility. ' +
            'The scan did not establish the local attacker model or whether the empty-token state is reachable in a supported deployment.',
    },
    {
        file: 'apps/server/src/http.ts',
        line: 848,
        oldFinding: OLD_SCAN_RESULTS[1],
        expectedClassification: 'investigationNote',
        oldClaimedLevel: 'impact-confirmed',
        actualDemonstratedLevel: 'logic-confirmed',
        missingEvidence: [
            'Trace attachment ownership through managedAttachmentStore.ts repository operations',
            'Trace whether attachment IDs are guessable or controllable by an attacker',
            'Trace whether cancelStaged, findClaimedById, or claimForAcceptedTurn accept unauthorized cross-owner operations',
            'Prove that a shared principal allows interference with another user\'s attachments',
            'Distinguish from the http.ts:310 root cause or prove materially different impact',
        ],
        rootCauseId: 'loopback-legacy-token-auth-bypass',
        threatModelEstablished: false,
        reviewVerdict: 'overstated',
        reviewNotes:
            'The shared principal is real. Cross-user attachment interference was not proven. ' +
            'Shares the same root cause as http.ts:310. Should not be an independent high-severity finding ' +
            'without proving ownership-impact through the repository layer.',
    },
    {
        file: 'apps/server/src/wsRpc.ts',
        line: 2042,
        oldFinding: OLD_SCAN_RESULTS[2],
        expectedClassification: 'investigationNote',
        oldClaimedLevel: 'exploit-confirmed',
        actualDemonstratedLevel: 'path-confirmed',
        missingEvidence: [
            'Establish the local attacker model (does the product treat untrusted local processes as attackers?)',
            'Trace which RPC methods are owner-only and reachable from the loopback session',
            'Trace whether shell command execution is actually reachable from the loopback session',
            'Prove that an unauthorized client can invoke a protected owner operation',
            'Do not claim "shell command execution" without tracing the specific RPC method path',
        ],
        rootCauseId: 'loopback-legacy-token-ws-owner-bypass',
        threatModelEstablished: false,
        reviewVerdict: 'design-risk',
        reviewNotes:
            'Owner-role assignment is real. The scan proved the branch returns null and the session becomes owner. ' +
            'But it did not trace which sensitive RPC capabilities are actually reachable. ' +
            'The claim of "shell command execution" was not independently verified. ' +
            'Vulnerability status depends on whether the product\'s threat model includes untrusted local processes.',
    },
];

// ── Precision acceptance criteria ───────────────────────────────────────────

export interface PrecisionAcceptanceCriteria {
    /**
     * The improved scanner must NOT produce any of the three old findings
     * as high-severity PROVEN vulnerabilities without the missing evidence.
     */
    noHighSeverityProvenWithoutEvidence: boolean;

    /**
     * Findings sharing a root cause must be correlated, not reported as
     * independent high-severity issues.
     */
    rootCauseCorrelation: boolean;

    /**
     * The scanner must establish the threat model before classifying
     * local/loopback behavior as a vulnerability.
     */
    threatModelRequired: boolean;

    /**
     * Pure-function or logic tests must not be classified as
     * impact-confirmed or exploit-confirmed.
     */
    verificationLevelAccuracy: boolean;

    /**
     * Capability claims (shell, file, MCP) must be traced, not assumed
     * from role assignment.
     */
    capabilityTracingRequired: boolean;

    /**
     * Configuration-dependent findings must inspect startup policy and
     * determine whether the unsafe state is reachable.
     */
    configurationInspectionRequired: boolean;
}

export const ACCEPTANCE_CRITERIA: PrecisionAcceptanceCriteria = {
    noHighSeverityProvenWithoutEvidence: true,
    rootCauseCorrelation: true,
    threatModelRequired: true,
    verificationLevelAccuracy: true,
    capabilityTracingRequired: true,
    configurationInspectionRequired: true,
};

// ── Test assertion helpers ──────────────────────────────────────────────────

/**
 * Assert that a scan result does NOT contain any of the old overstated
 * findings as high-severity PROVEN vulnerabilities.
 *
 * This is the primary regression test for the precision-first improvements.
 */
export function assertNoOverstatedFindings(
    results: Array<{
        file: string;
        line: number;
        type: string;
        severity: string;
        proven?: string;
        verificationLevel?: string;
    }>,
): { passed: boolean; violations: string[] } {
    const violations: string[] = [];

    for (const result of results) {
        for (const old of OLD_SCAN_RESULTS) {
            if (
                result.file === old.file &&
                result.line === old.line &&
                result.type === old.type &&
                result.severity === old.severity
            ) {
                const isProven =
                    result.proven === 'PROVEN' ||
                    result.verificationLevel === 'impact-confirmed' ||
                    result.verificationLevel === 'exploit-confirmed';
                if (isProven) {
                    violations.push(
                        `${old.file}:${old.line} was classified as PROVEN/impact-confirmed without the required evidence chain. ` +
                            `Expected: investigationNote or coverageGap until threat model, configuration state, and impact are established.`,
                    );
                }
            }
        }
    }

    return { passed: violations.length === 0, violations };
}
