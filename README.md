# SecureCode MCP

Standalone MCP (Model Context Protocol) server for SecureCode AI. It gives AI coding assistants — Cursor, Claude Code, Codex, Windsurf and other MCP clients — an AI security investigator that proves its findings with real tests in a sandbox.

## What's new in 0.13

- **One scanner: the agent scan.** The old regular scan pipeline, `securecode.scan`, `securecode.scan-batch`, `securecode.attack`, runtime probes and the VS Code extension are retired.
- **Two modes:** `standard` (default — investigation, sandbox proofs, fixes) and `deep` (beta — adds a threat checklist and attack tests, with one approval at the start of the scan).
- **Smarter, less rigid investigation.** Evidence the scanner thinks is missing is now attached to the finding as open questions instead of rejecting the agent's finish; the AI reviewer judges who the attacker is and what they gain. Scans that did their job end as complete and are cached.
- **Every finding says whether the AI reviewer checked it** (`aiReview`), separately from why the scan stopped and from its proof verdict (`proven`).
- **More languages:** framework-aware proofs for Express (full), other JavaScript/TypeScript and Python frameworks (beta); Go, Ruby, PHP, Java and .NET run in Docker sandboxes when Docker and the project's dependencies are available.
- **`securecode.memory`** replaces the four memory tools; `decide-finding` with decision `clear` replaces `clear-finding-reviews`.
- **scan-dependencies** reads full advisories (real severities, smallest safe upgrade) across 13 lockfile formats; **scan-secrets** was rebuilt.
- CLI: `securecode-mcp scan --mode <standard|deep>`; `--depth` was removed.

## Install

```bash
npm install -g @securecode-ai/mcp
```

Or use directly with npx (no install needed):

```bash
npx @securecode-ai/mcp scan src/app.ts
```

## Quick Start

```bash
securecode-mcp login              # Authenticate (email code or password)
securecode-mcp doctor             # Verify your setup works
securecode-mcp scan src/app.ts    # Scan a file from the CLI
securecode-mcp update             # Update to the latest version
securecode-mcp serve              # Start the MCP server (for AI clients)
```

## CLI Commands

```bash
securecode-mcp serve [--workspace <path>]          Start the MCP stdio server
securecode-mcp login [--password] [--api-url <url>] Authenticate via email code or password
securecode-mcp status                               Show current auth status
securecode-mcp logout                               Remove stored credentials
securecode-mcp scan <filePath> [--json]             Scan a single file
  [--mode <standard|deep>] [--workspace <path>]
securecode-mcp doctor                               Verify setup (credentials, API, parser)
securecode-mcp update                               Update to the latest published version
securecode-mcp version                              Show the installed version
securecode-mcp --help                               Show help
```

### Scan from CLI

```bash
# Standard agent scan (default)
securecode-mcp scan src/app/api/users/route.ts

# Deep scan (beta): threat checklist + attack tests, asks for one approval at the start
securecode-mcp scan src/app/api/users/route.ts --mode deep

# JSON output for CI
securecode-mcp scan src/app.ts --json

# Exit codes: 0 = no findings, 1 = findings found, 2 = error
```

### CI/CD Example

```yaml
# GitHub Action
- name: SecureCode scan
  run: |
    npm install -g @securecode-ai/mcp
    securecode-mcp scan src/app.ts --json > scan-results.json
  env:
    SECURECODE_API_TOKEN: ${{ secrets.SECURECODE_API_TOKEN }}
```

## MCP client configuration

### Cursor / Windsurf

```json
{
  "mcpServers": {
    "securecode": {
      "command": "npx",
      "args": ["-y", "@securecode-ai/mcp@latest", "serve", "--workspace", "/path/to/your/project"],
      "env": {
        "SECURECODE_API_TOKEN": "your-api-token-here"
      }
    }
  }
}
```

Or if installed globally:

```json
{
  "mcpServers": {
    "securecode": {
      "command": "securecode-mcp",
      "args": ["serve", "--workspace", "/path/to/your/project"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add securecode -s user -- securecode-mcp serve --workspace /path/to/your/project
```

## Tools (15)

### Scanning

| Tool | Description | Approval |
|------|-------------|----------|
| `securecode.agent-scan` | AI security investigation of one file, with sandbox proofs; `mode`: `standard` (default) or `deep` (beta) | Deep mode: once per scan |
| `securecode.agent-scan-batch` | Map + architecture scout, then agent-scan the top files one at a time | No |
| `securecode.scan-secrets` | Hardcoded secrets and PII (local, no AI) | No |
| `securecode.scan-dependencies` | Lockfiles checked against OSV/GitHub/NVD advisories, with the smallest safe upgrade | No |

### Background Scan Jobs

| Tool | Description | Approval |
|------|-------------|----------|
| `securecode.agent-scan-start` | Start an agent scan in the background; returns `{ jobId, status, estimatedMinutes }` immediately | No |
| `securecode.agent-scan-batch-start` | Start an agent-scan batch in the background | No |
| `securecode.job-status` | Status and progress of a job (latest job if `jobId` is omitted); includes the full result when completed | No |
| `securecode.job-cancel` | Cancel a running job (findings so far are kept) | No |
| `securecode.job-list` | Recent jobs in this workspace (last 50, up to 7 days) | No |

Long scans run in the background, so your AI client never hits its tool-call timeout. `securecode.agent-scan` and
`securecode.agent-scan-batch` still return the normal result when the scan finishes within ~50 seconds
(`SECURECODE_TOOL_WAIT_MS`); otherwise they return `{ "status": "running", "jobId": "..." }` and the agent checks back
with `securecode.job-status` about every 60 seconds. Only one agent scan runs per workspace at a time: starting the same
file again returns the running job, and starting a different scan returns `busy` with the running job's id. Job records
are kept in `.securecode/jobs/`; a job whose MCP process stopped (client restart, crash) is marked `interrupted` the next
time the server starts, and its API run is closed.

### Project Analysis

| Tool | Description | Approval |
|------|-------------|----------|
| `securecode.architecture` | AI architecture scout: ranked important files, trust boundaries, security controls, recommended scan order (uses AI credits, cached per depth) | No |

### Fixes & Testing

| Tool | Description | Approval |
|------|-------------|----------|
| `securecode.fix` | Generate a patch for a finding; the fix is re-tested against the original proof | Yes |
| `securecode.run-tests` | Run the project's tests or a generated test in the sandbox | Yes |

### Agent Memory and Finding Review

| Tool | Description | Approval |
|------|-------------|----------|
| `securecode.memory` | `list`, `add-fact`, `record-false-positive` or `clear` the agent's per-workspace memory | No |
| `securecode.review-findings` | Review the finding queue for a workspace | No |
| `securecode.decide-finding` | Mark review-queue findings `confirmed`, `rejected` (also recorded as a false positive), `deferred`, or `clear` them | No |

When the agent reports a false positive, dismiss it with `securecode.memory` (action `record-false-positive`). The pattern is stored in `.securecode/agent-memory.json` and similar patterns are not reported in later scans of that workspace. Memory is per-workspace, user-owned and deletable.

## How the agent scan works

The agent scan (`securecode.agent-scan`) is an AI security investigator. It:

1. **Reads** the target file (shown to it in full when small) and the related files it needs
2. **Traces** data flows (taint tracking, cross-file flows) and **checks** guards, endpoint policies and configuration
3. **Writes a self-critique**, then an **independent AI reviewer** checks the findings before they are accepted
4. **Proves** findings with tests it writes, run against the real code in a sandbox (Docker, or a local sandbox)
5. **Generates fixes** for proven findings and re-tests them (standard mode)

In `deep` mode (beta) it also builds a threat checklist for the file, adds red-team rounds, and runs attack tests in the sandbox after one approval at the start of the scan.

Agent tools: `read_file`, `search_code`, `trace_flow`, `trace_flow_cross_file`, `check_guard`, `check_policy`, `list_files`, `read_config`, `check_dependencies`, `run_tests`, `finish`.

### What each finding tells you

- **`proven`** — `PROVEN` only when a sandbox test against the real code showed the attack working: a passing normal case, a successful exploit with observed impact, three repeat runs, and (where possible) a mutation check that the test fails once the bug is fixed. Otherwise `INCONCLUSIVE`, `UNPROVEN`, `NOT_REPRODUCIBLE` or `SKIPPED` (low severity).
- **`aiReview`** — whether the AI reviewer checked the finding (`reviewed`, `not-reviewed` with the reason, or `unknown` for results from older servers or caches).
- **`openQuestions`** — evidence the scanner could not see, such as "no traced flow reached this line" or "no guard check was run here". A proof answers them, so proven findings carry none.
- **`terminationReason`** — why the scan stopped (`agent_finish`, or a budget or time limit). It says nothing about whether a finding is real; read `proven` for that.

The scanner keeps strict rules only where they protect the result: the sandbox and its safety checks, the proof rules above, budgets and time limits, and stopping loops of repeated identical actions. Coverage checks still ask the agent to read security-relevant code it skipped and the lines a finding cites.

### Languages

- **Express (JavaScript/TypeScript):** full support, proofs on the real Express app in-process.
- **Other JavaScript/TypeScript and Python frameworks** (Fastify, NestJS, Next.js, Koa, Hono, FastAPI, Flask, Django): beta.
- **Go, Ruby, PHP, Java and .NET:** AI review, with proofs when Docker and the project's dependencies are available (offline sandbox; dependencies come from local caches).

### Credits

An agent scan uses 5 credits; large files can use up to 15 (extended 2 credits at a time) and unused extension credits are refunded. Files over 2,000 lines are scanned in parts; each part uses 5–15 credits. Parts run one after another and the result is merged into one file result.

## Tool Errors and Progress

**Failures say what to do, not just what broke.** A missing or expired session
returns `"Not authenticated — run securecode-mcp login and retry"`, not a bare
`Unauthorized`. Insufficient credits name the amounts and point at the top-up
page; daily limits say so; network failures say to check the connection.

The architecture scout pre-flights auth on every start, so a doomed scout never
reports `"started"`. If a background start fails anyway, the next poll returns:

```json
{ "status": "failed", "error": "Not authenticated — ...", "remedy": "Run `securecode-mcp login` and retry.", "retryable": false }
```

Retry after fixing the cause — the same call re-starts the scout automatically.
Run-pool contention (409, another scan mid-flight) is still reported as
`in-progress` with a wait hint, because waiting is the correct action there.

**Progress works in every client, no `progressToken` needed.** The
architecture tool is fast-return + poll by design (MCP clients time out long
calls), so each poll response carries live progress:

```json
{ "status": "in-progress", "progress": { "done": 12, "total": 40 }, "lastMessage": "Reading apps/server/src/http.ts (step 12)", "elapsedMs": 214000, "etaMinutes": 2 }
```

Long synchronous tools (agent-scan, fix) additionally emit standard MCP
`notifications/progress` when the client sends a `progressToken` — that lights
up automatically in clients that support it.

**Cancelling works.** The server honors MCP `notifications/cancelled` — aborting
a tool call in your client fires an AbortSignal through the running scan, which
closes the run server-side (cancelled) and salvages findings found so far.
Background jobs are cancelled with `securecode.job-cancel`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURECODE_API_TOKEN` | — | API token (alternative to login) |
| `SECURECODE_API_URL` | `https://api.usesecurecode.tech` | API base URL |
| `SECURECODE_TOOL_WAIT_MS` | `50000` | How long `agent-scan` / `agent-scan-batch` wait for a result before returning `{ status: "running", jobId }` |
| `SECURECODE_SANDBOX` | auto | Force a sandbox: `docker`, `local`, `deno`, or `none` (no proofs) |
| `SECURECODE_SANDBOX_IMAGE` | `node:22-alpine` | Docker image for JavaScript/TypeScript proofs (per-language overrides: `SECURECODE_SANDBOX_PY_IMAGE`, `_GO_IMAGE`, `_RUBY_IMAGE`, `_PHP_IMAGE`, `_JAVA_MAVEN_IMAGE`, `_JAVA_GRADLE_IMAGE`, `_DOTNET_IMAGE`) |

## Security

- Credentials stored in OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service) with file fallback (`~/.securecode/credentials.json`, mode 0600).
- File reads are confined to the `--workspace` root.
- Proof tests run in a sandbox with no network, a read-only workspace and resource limits; every test script passes static safety checks first.
- Fixes are returned for review and never auto-applied.
- Agent memory is per-workspace (`.securecode/agent-memory.json`), never sent to the API.
- No telemetry.

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT
