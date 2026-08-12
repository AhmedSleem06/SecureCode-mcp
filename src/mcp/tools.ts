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
                    description: 'Language id (javascript, typescript, python, php). Inferred from filePath if omitted.',
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
                    description: 'Language id (javascript, typescript, python, php).',
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
];
