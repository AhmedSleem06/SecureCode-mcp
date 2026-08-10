#!/usr/bin/env node

import * as path from 'path';
import { CredentialStore } from './auth/credentialStore';
import { startServer } from './mcp/server';
import type { ServerContext } from './mcp/types';

function printUsage(): void {
    console.log(`SecureCode MCP — standalone security scanner for AI coding tools

Usage:
  securecode-mcp serve [--workspace <path>]    Start the MCP stdio server
  securecode-mcp login [--api-url <url>]        Store your API token
  securecode-mcp status                        Show current auth status
  securecode-mcp logout                        Remove stored credentials
  securecode-mcp --help                        Show this help

Environment:
  SECURECODE_API_TOKEN    API token (alternative to login)
  SECURECODE_API_URL      API base URL (default: https://api.usesecurecode.tech)

MCP client configuration (Cursor, Claude Code, Windsurf, Codex):
  {
    "mcpServers": {
      "securecode": {
        "command": "securecode-mcp",
        "args": ["serve", "--workspace", "/path/to/your/project"]
      }
    }
  }
`);
}

async function cmdServe(args: string[]): Promise<void> {
    let workspace = process.cwd();
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--workspace' && i + 1 < args.length) {
            workspace = path.resolve(args[++i]);
        }
    }

    if (!path.isAbsolute(workspace)) {
        workspace = path.resolve(workspace);
    }

    const creds = CredentialStore.getOrThrow();

    const ctx: ServerContext = {
        apiUrl: creds.apiUrl,
        apiToken: creds.apiToken,
        workspaceRoot: workspace,
    };

    startServer(ctx);
}

async function cmdLogin(args: string[]): Promise<void> {
    let apiUrl = 'https://api.usesecurecode.tech';
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--api-url' && i + 1 < args.length) {
            apiUrl = args[++i];
        }
    }

    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = (q: string) => new Promise<string>((resolve) => rl.question(q, resolve));

    console.log('SecureCode MCP Login');
    console.log(`API URL: ${apiUrl}`);
    console.log('');

    const token = await ask('Enter your SecureCode API token: ');
    rl.close();

    if (!token || token.trim().length === 0) {
        console.error('Error: No token provided.');
        process.exit(1);
    }

    CredentialStore.save({
        apiToken: token.trim(),
        apiUrl,
        storedAt: new Date().toISOString(),
    });

    console.log('');
    console.log('Credentials saved to ~/.securecode/credentials.json');
    console.log('You can now run: securecode-mcp serve --workspace /path/to/project');
}

function cmdStatus(): void {
    const creds = CredentialStore.get();
    if (!creds) {
        console.log('Not authenticated. Run: securecode-mcp login');
        process.exit(0);
    }

    console.log('Authenticated');
    console.log(`  API URL: ${creds.apiUrl}`);
    console.log(`  Token: ${creds.apiToken.substring(0, 8)}...${creds.apiToken.slice(-4)}`);
    console.log(`  Stored: ${creds.storedAt}`);
}

function cmdLogout(): void {
    const removed = CredentialStore.clear();
    if (removed) {
        console.log('Credentials removed.');
    } else {
        console.log('No stored credentials found.');
    }
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const command = args[0];

    if (!command || command === '--help' || command === '-h') {
        printUsage();
        process.exit(0);
    }

    const subArgs = args.slice(1);

    switch (command) {
        case 'serve':
            await cmdServe(subArgs);
            break;
        case 'login':
            await cmdLogin(subArgs);
            break;
        case 'status':
            cmdStatus();
            break;
        case 'logout':
            cmdLogout();
            break;
        default:
            console.error(`Unknown command: ${command}`);
            printUsage();
            process.exit(1);
    }
}

main().catch((err) => {
    console.error(err.message || String(err));
    process.exit(1);
});
