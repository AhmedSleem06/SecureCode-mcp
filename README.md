# SecureCode MCP

Standalone MCP (Model Context Protocol) server for SecureCode AI. Provides security scanning tools to AI coding assistants — Cursor, Claude Code, Codex, Windsurf, and other compatible MCP clients — without requiring the VS Code extension.

## Install

```bash
npm install -g @securecode-ai/mcp
```

## Quick Start

```bash
securecode-mcp login              # Authenticate (email + OTP)
securecode-mcp doctor             # Verify your setup works
securecode-mcp scan src/app.ts    # Scan a file from the CLI
securecode-mcp serve              # Start the MCP server (for AI clients)
```

## CLI Commands

```bash
securecode-mcp serve [--workspace <path>]         Start the MCP stdio server
securecode-mcp login [--api-url <url>]             Authenticate via email + OTP
securecode-mcp status                              Show current auth status
securecode-mcp logout                              Remove stored credentials
securecode-mcp scan <filePath> [--json]            Scan a single file
  [--depth <fast|deep|agent>] [--workspace <path>]
securecode-mcp doctor                              Verify setup (credentials, API, scan)
securecode-mcp --help                              Show help
```

### Scan from CLI

```bash
# Agent scan (deep, AI-powered)
securecode-mcp scan src/app/api/users/route.ts

# Fast scan (no AI, free, <5s)
securecode-mcp scan src/lib/auth.ts --depth fast

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
    securecode-mcp login  # or set SECURECODE_API_TOKEN
    securecode-mcp scan src/ --json > scan-results.json
    # Exit 1 if findings found
```

## MCP client configuration

### Cursor / Windsurf

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

## Tools (11)

### Scanning

| Tool | Description | Approval |
|------|-------------|----------|
| `securecode.scan` | Scan code for vulnerabilities (AI pipeline) | No |
| `securecode.agent-scan` | Agent-mode deep scan with 10 tools + sandbox proof | No |
| `securecode.scan-batch` | Scan multiple files in one call | No |
| `securecode.scan-secrets` | Scan for hardcoded secrets and PII (local, no AI) | No |
| `securecode.scan-dependencies` | Scan lockfiles for known vulnerabilities (OSV/NVD) | No |

### Project Analysis

| Tool | Description | Approval |
|------|-------------|----------|
| `securecode.map` | Get the Project Map (endpoints, middleware, auth) | No |

### Fixes & Testing

| Tool | Description | Approval |
|------|-------------|----------|
| `securecode.fix` | Generate a patch for a specific finding | Yes |
| `securecode.attack` | Endpoint red-team testing (beta) | Yes |

### Agent Memory (FP Learning)

| Tool | Description | Approval |
|------|-------------|----------|
| `securecode.record-false-positive` | Dismiss a finding as FP — agent learns not to report it | No |
| `securecode.get-agent-memory` | View learned false positives and known facts | No |
| `securecode.clear-agent-memory` | Clear all agent memory (or one FP by ID) | No |
| `securecode.add-known-fact` | Add a project fact for faster investigations | No |

### How Agent Memory Works

When the agent reports a false positive, dismiss it with `record-false-positive`. The agent stores the pattern in `.securecode/agent-memory.json` and will not report similar patterns in future scans of that workspace.

```
Scan 1: Agent reports csp_bypass → You dismiss as "intentional design"
Scan 2: Agent sees the FP memory → skips similar patterns → fewer false positives
```

Memory is per-workspace, user-owned, and deletable. No cross-tenant leakage.

## Agent Scan Architecture

The agent scan (`securecode.agent-scan`) is an AI investigator that:

1. **Reads** the target file and related files (10 tools)
2. **Traces** data flows (taint tracking, cross-file)
3. **Checks** guards and endpoint policies
4. **Self-critiques** before reporting (selfCritique field)
5. **Gets reviewed** by an independent critique LLM
6. **Proves** findings in a sandbox (PROVEN/UNPROVEN)
7. **Generates fixes** for proven findings

Agent tools: `read_file`, `search_code`, `trace_flow`, `trace_flow_cross_file`, `check_guard`, `check_policy`, `get_endpoints`, `list_imports`, `list_files`, `finish`.

Languages: JavaScript, TypeScript, Python (partial).

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURECODE_API_TOKEN` | — | API token (alternative to login) |
| `SECURECODE_API_URL` | `https://api.usesecurecode.tech` | API base URL |

## Security

- Credentials stored in OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service) with file fallback (`~/.securecode/credentials.json`, mode 0600).
- File reads are confined to the `--workspace` root.
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
