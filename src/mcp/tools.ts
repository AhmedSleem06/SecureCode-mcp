import type { ToolDef } from './types';

export const TOOLS: ToolDef[] = [
    {
        name: 'securecode.scan',
        description:
            'Scan a source file or code string for vulnerabilities. Read-only: no approval needed. Returns findings (type, severity, location, message, evidence). Uses the SecureCode AI multi-phase pipeline (Scout discovery, Juror verification, Reconcile).',
        inputSchema: {
            type: 'object',
            properties: {
                code: {
                    type: 'string',
                    description: 'Source code to scan (if filePath is omitted).',
                },
                filePath: {
                    type: 'string',
                    description: 'Workspace-relative path to the file to scan (reads from disk within the workspace root).',
                },
                language: {
                    type: 'string',
                    description: 'Language id (javascript, typescript, python). Inferred from filePath if omitted.',
                },
                scanDepth: {
                    type: 'string',
                    enum: ['fast', 'deep', 'auto'],
                    description: 'Scan depth: "fast" = deterministic-only (sink floor + secret scan, <5s, no AI), "deep" = full AI pipeline (Scout + Juror + consensus), "auto" = deep with standard reasoning effort. Default: auto.',
                },
            },
        },
    },
    {
        name: 'securecode.map',
        description:
            'Get or build the Project Map for the workspace — extracted endpoints, middleware, auth scheme, and ORM. Read-only: no approval needed. Actions: "endpoints" (default, returns the endpoint list), "status" (map metadata), "build" (rebuild the map from source).',
        inputSchema: {
            type: 'object',
            properties: {
                action: {
                    type: 'string',
                    enum: ['status', 'endpoints', 'build'],
                    description: 'What to do: "status" for map metadata, "endpoints" for the endpoint list (default), "build" to rebuild the map from source.',
                },
            },
        },
    },
    {
        name: 'securecode.fix',
        description:
            'Generate a patch for a specific vulnerability finding. REQUIRES human approval before executing. Returns the fixed code + diff + explanation. Does NOT auto-apply; the human reviews and applies the patch.',
        inputSchema: {
            type: 'object',
            properties: {
                code: {
                    type: 'string',
                    description: 'The source code containing the vulnerability.',
                },
                filePath: {
                    type: 'string',
                    description: 'Workspace-relative path to the file (reads from disk if code is omitted).',
                },
                language: {
                    type: 'string',
                    description: 'Language id (javascript, typescript, python).',
                },
                vulnerabilityType: {
                    type: 'string',
                    description: 'Vulnerability type (e.g. sql_injection, xss, missing_authorization).',
                },
                lineStart: {
                    type: 'number',
                    description: '1-indexed start line of the finding.',
                },
                lineEnd: {
                    type: 'number',
                    description: '1-indexed end line of the finding.',
                },
                evidenceSnippet: {
                    type: 'string',
                    description: 'The vulnerable code snippet.',
                },
                framework: {
                    type: 'string',
                    description: 'Optional framework hint (e.g. express, nextjs, fastapi).',
                },
            },
            required: ['code', 'language', 'vulnerabilityType', 'lineStart', 'lineEnd', 'evidenceSnippet'],
        },
    },
    {
        name: 'securecode.attack',
        description:
            'Request an endpoint red-team attack against a localhost dev server. REQUIRES human approval. The target must be a mapped endpoint from the Project Map and the dev server must already be running on localhost. Beta: localhost targets only.',
        inputSchema: {
            type: 'object',
            properties: {
                filePath: {
                    type: 'string',
                    description: 'Workspace-relative path to the source file containing the endpoint.',
                },
                code: {
                    type: 'string',
                    description: 'Source code to analyze (if filePath is omitted).',
                },
                language: {
                    type: 'string',
                    description: 'Language id.',
                },
                vulnerabilityType: {
                    type: 'string',
                    description: 'Optional — skip auto-scan and attack this vulnerability type.',
                },
                lineStart: {
                    type: 'number',
                    description: 'Optional — 1-indexed start line of the finding to attack.',
                },
                lineEnd: {
                    type: 'number',
                    description: 'Optional — 1-indexed end line of the finding.',
                },
                evidenceSnippet: {
                    type: 'string',
                    description: 'Optional — vulnerable code snippet for the finding.',
                },
            },
        },
    },
    {
        name: 'securecode.scan-dependencies',
        description:
            'Scan local lockfiles for known vulnerabilities using OSV.dev + GitHub Advisory + NVD. Read-only: no approval needed. Runs entirely locally — only package name+version leave the machine. Supports package-lock.json, yarn.lock, pnpm-lock.yaml, Pipfile.lock, requirements.txt. Returns findings with severity, installed version, fix version, and license info.',
        inputSchema: {
            type: 'object',
            properties: {},
        },
    },
    {
        name: 'securecode.scan-batch',
        description:
            'Scan multiple files for vulnerabilities in one call. Discovers scannable files from a directory or explicit file list. Each file runs the full scan pipeline (Scout → Juror → Phase3). Read-only: no approval needed. Stops early on credit exhaustion or maxFiles cap. Use for scanning a folder or a set of files at once.',
        inputSchema: {
            type: 'object',
            properties: {
                directory: {
                    type: 'string',
                    description: 'Workspace-relative folder to scan recursively (mutually exclusive with filePaths).',
                },
                filePaths: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Explicit workspace-relative paths to scan (mutually exclusive with directory).',
                },
                maxFiles: {
                    type: 'number',
                    description: 'Cap on files scanned (default 200).',
                },
                includeTests: {
                    type: 'boolean',
                    description: 'Include test files (.test.ts, .spec.js, __tests__/). Default: false — test files are skipped to save credits.',
                },
            },
        },
    },
    {
        name: 'securecode.scan-secrets',
        description:
            'Scan files for hardcoded secrets and PII — API keys, JWTs, private keys, database URLs, credentials, emails, credit cards. Runs entirely locally (no AI, no API calls, no credits). Scans a directory or explicit file list. Respects .securecodeignore. Use for CI/secret-audit workflows.',
        inputSchema: {
            type: 'object',
            properties: {
                directory: {
                    type: 'string',
                    description: 'Workspace-relative folder to scan recursively (mutually exclusive with filePaths).',
                },
                filePaths: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Explicit workspace-relative paths to scan (mutually exclusive with directory).',
                },
                maxFiles: {
                    type: 'number',
                    description: 'Cap on files scanned (default 200).',
                },
            },
        },
    },
    {
        name: 'securecode.agent-scan',
        description:
            'Agent-mode scan: an AI investigator that reads files, traces data flows, checks guards, and compares endpoint policies to find vulnerabilities. Slower but deeper than a deep scan. The agent replaces the Scout phase and its findings are verified by the Juror. Uses 5 scan credits. Best for complex access-control and cross-file vulnerabilities.',
        inputSchema: {
            type: 'object',
            properties: {
                code: {
                    type: 'string',
                    description: 'Source code to scan (if filePath is omitted).',
                },
                filePath: {
                    type: 'string',
                    description: 'Workspace-relative path to the file to scan (reads from disk within the workspace root).',
                },
                language: {
                    type: 'string',
                    description: 'Language id (javascript, typescript, python). Inferred from filePath if omitted.',
                },
            },
        },
    },
    {
        name: 'securecode.record-false-positive',
        description:
            'Dismiss a vulnerability finding as a false positive. The agent learns from this and will not report similar patterns in future scans of this workspace. Stored per-workspace in .securecode/agent-memory.json. Use when the user marks a finding as "not a vulnerability".',
        inputSchema: {
            type: 'object',
            properties: {
                filePath: {
                    type: 'string',
                    description: 'Workspace-relative path to the file where the finding was reported.',
                },
                findingType: {
                    type: 'string',
                    description: 'The vulnerability type of the finding (e.g. sql_injection, broken_access_control, missing_rate_limiting, information_disclosure, user_enumeration).',
                },
                line: {
                    type: 'number',
                    description: 'Line number of the finding.',
                },
                evidence: {
                    type: 'string',
                    description: 'The evidence string from the finding (code snippet or description).',
                },
                reason: {
                    type: 'string',
                    description: 'Why this is a false positive (user\'s explanation).',
                },
                pattern: {
                    type: 'string',
                    description: 'Optional short pattern description. If omitted, derived from evidence.',
                },
                codeSnippet: {
                    type: 'string',
                    description: 'Optional code snippet for context.',
                },
            },
            required: ['filePath', 'findingType', 'line', 'evidence', 'reason'],
        },
    },
    {
        name: 'securecode.get-agent-memory',
        description:
            'View the agent\'s learned memory for this workspace — false positives and known facts. Read-only. Use to review what the agent has learned before running a scan.',
        inputSchema: {
            type: 'object',
            properties: {},
        },
    },
    {
        name: 'securecode.clear-agent-memory',
        description:
            'Clear the agent\'s learned memory for this workspace. If "id" is provided, removes only that false positive. Otherwise clears all memory (false positives + known facts). Stored in .securecode/agent-memory.json.',
        inputSchema: {
            type: 'object',
            properties: {
                id: {
                    type: 'string',
                    description: 'Optional: ID of a specific false positive to remove. If omitted, clears ALL memory.',
                },
            },
        },
    },
    {
        name: 'securecode.add-known-fact',
        description:
            'Add a fact about the project the agent should know in future scans (e.g. "Project uses requireMembership for auth"). Helps the agent investigate faster by not re-discovering known structural facts.',
        inputSchema: {
            type: 'object',
            properties: {
                fact: {
                    type: 'string',
                    description: 'The fact to store (e.g. "Project uses requireMembership for membership auth, isProjectOwner for ownership").',
                },
                source: {
                    type: 'string',
                    description: 'Where this fact was discovered (e.g. "src/lib/authz.ts:12").',
                },
            },
            required: ['fact', 'source'],
        },
    },
    {
        name: 'securecode.run-tests',
        description:
            'Run tests in a sandbox with human approval. Two modes: "existing" runs the workspace test suite (npm/pnpm/yarn/bun test, pytest) with a strict command allowlist — no shell operators, no install/build/publish, only the test lifecycle. "generated" runs an inline test script (node/tsx/bun/deno/python) through the verification sandbox with safety checks. Every execution requires human approval; tests run inside a Docker/Deno sandbox with network disabled, read-only workspace, and resource limits. Does NOT install dependencies. Use securecode.find-tests or the find_tests agent action to discover test files first.',
        inputSchema: {
            type: 'object',
            properties: {
                mode: {
                    type: 'string',
                    enum: ['existing', 'generated'],
                    description: 'Execution mode: "existing" runs the workspace test suite via package manager; "generated" runs an inline test script via a runner.',
                },
                testFiles: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Existing mode: workspace-relative test file paths to run (e.g. ["tests/auth.test.ts"]). Max 50 files.',
                },
                testPattern: {
                    type: 'string',
                    description: 'Existing mode: test name pattern passed to the runner (e.g. "auth" for -k auth in pytest, or a grep pattern). Max 200 chars.',
                },
                packageManager: {
                    type: 'string',
                    enum: ['npm', 'pnpm', 'yarn', 'bun', 'pytest'],
                    description: 'Existing mode: package manager to use. Auto-detected if omitted (defaults to npm).',
                },
                script: {
                    type: 'string',
                    description: 'Generated mode: inline test script source code. Max 64KB. Must print PASS: or FAIL: markers for verdict parsing.',
                },
                runner: {
                    type: 'string',
                    enum: ['node', 'tsx', 'bun', 'deno', 'python', 'python3'],
                    description: 'Generated mode: runner to execute the script.',
                },
                setupScript: {
                    type: 'string',
                    description: 'Generated mode: optional setup script run before the test in the same sandbox. Max 32KB.',
                },
                timeoutMs: {
                    type: 'number',
                    description: 'Hard timeout in milliseconds. Default: 60000 (existing), 30000 (generated). Max: 300000.',
                },
            },
            required: ['mode'],
        },
    },
];
