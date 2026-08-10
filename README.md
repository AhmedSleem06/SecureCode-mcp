# SecureCode MCP

Standalone MCP (Model Context Protocol) server for SecureCode AI. Provides security scanning tools to AI coding assistants — Cursor, Claude Code, Codex, Windsurf, and other compatible MCP clients — without requiring the VS Code extension.

## Install

```bash
npm install -g @securecode-ai/mcp
```

## Authenticate

```bash
securecode-mcp login
```

Or set the `SECURECODE_API_TOKEN` environment variable.

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

## Tools

| Tool | Description | Approval |
|------|-------------|----------|
| `securecode.scan` | Scan code for vulnerabilities using the AI pipeline | No |
| `securecode.map` | Get the Project Map (endpoints, middleware, auth) | No |
| `securecode.fix` | Generate a patch for a specific finding | Yes |
| `securecode.attack` | Endpoint red-team testing (beta) | Yes |

## CLI

```bash
securecode-mcp serve [--workspace <path>]    Start the MCP stdio server
securecode-mcp login [--api-url <url>]      Store your API token
securecode-mcp status                       Show auth status
securecode-mcp logout                       Remove credentials
```

## Security

- No API token in MCP client configuration — credentials are stored in `~/.securecode/credentials.json` (mode 0600) or the `SECURECODE_API_TOKEN` env var.
- File reads are confined to the `--workspace` root.
- Fixes are returned for review and never auto-applied.
- No telemetry.

## Development

```bash
npm install
npm run build
npm test
```
