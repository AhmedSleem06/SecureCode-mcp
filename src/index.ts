#!/usr/bin/env node

import * as path from 'path';
import * as fs from 'fs';
import { CredentialStore } from './auth/credentialStore';
import { startServer } from './mcp/server';
import type { ServerContext } from './mcp/types';
import { ApiClient } from './api/client';

function printUsage(): void {
    console.log(`SecureCode MCP — standalone security scanner for AI coding tools

Usage:
  securecode-mcp serve [--workspace <path>]    Start the MCP stdio server
  securecode-mcp login [--api-url <url>]        Authenticate via email + OTP
  securecode-mcp status                        Show current auth status
  securecode-mcp logout                        Remove stored credentials
  securecode-mcp scan <filePath> [--json]      Scan a single file for vulnerabilities
  securecode-mcp doctor                        Verify setup (credentials, API, scan)
  securecode-mcp --help                        Show this help

Scan options:
  --json                    Output results as JSON (for CI/automation)
  --depth <fast|deep|agent>  Scan depth (default: agent). "fast" = no AI, "deep" = full pipeline
  --workspace <path>        Workspace root (default: current directory)

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

    // Step 1: Ask for email
    const email = (await ask('Enter your email: ')).trim();
    if (!email || !email.includes('@')) {
        console.error('Error: A valid email is required.');
        rl.close();
        process.exit(1);
    }

    // Step 2: Check if the email exists
    console.log('');
    console.log('Checking account...');
    try {
        await ApiClient.postJsonNoAuth(apiUrl, '/auth/check-email', { email });
    } catch (err: any) {
        if (err.status === 404 || err.message?.toLowerCase().includes('not')) {
            console.error(`Error: No account found for ${email}. Sign up at https://usesecurecode.tech first.`);
        } else {
            console.error(`Error: ${err.message || err}`);
        }
        rl.close();
        process.exit(1);
    }

    // Step 3: Send OTP
    console.log('Sending verification code...');
    try {
        await ApiClient.postJsonNoAuth(apiUrl, '/auth/send-otp', { email });
    } catch (err: any) {
        console.error(`Error sending code: ${err.message || err}`);
        rl.close();
        process.exit(1);
    }

    // Step 4: Ask for the OTP code
    console.log(`A 6-digit verification code was sent to ${email}.`);
    const otp = (await ask('Enter the code: ')).trim();
    if (!otp || otp.length < 4) {
        console.error('Error: A valid verification code is required.');
        rl.close();
        process.exit(1);
    }
    rl.close();

    // Step 5: Verify OTP → get JWT
    console.log('Verifying...');
    let token: string;
    let plan: string;
    try {
        const resp = await ApiClient.postJsonNoAuth(apiUrl, '/auth/verify-otp', { email, otp });
        token = resp.token;
        plan = resp.plan || 'free';
        if (!token) {
            console.error('Error: No token returned from verification.');
            process.exit(1);
        }
    } catch (err: any) {
        console.error(`Error: ${err.message || err}`);
        process.exit(1);
    }

    // Step 6: Store the token
    const result = CredentialStore.save({
        apiToken: token,
        apiUrl,
        storedAt: new Date().toISOString(),
    });

    console.log('');
    console.log(`Authenticated (${plan} plan).`);
    if (result.method === 'keychain') {
        console.log('Token saved to OS keychain.');
    } else {
        console.log('Token saved to ~/.securecode/credentials.json (mode 0600).');
        if (result.warning) {
            console.log(`Warning: ${result.warning}`);
        }
    }
    console.log('');
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
    console.log(`  Storage: ${creds.storedAt}`);
}

function cmdLogout(): void {
    const removed = CredentialStore.clear();
    if (removed) {
        console.log('Credentials removed.');
    } else {
        console.log('No stored credentials found.');
    }
}

async function cmdScan(args: string[]): Promise<void> {
    let filePath = '';
    let jsonOutput = false;
    let depth = 'agent';
    let workspace = process.cwd();

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--json') {
            jsonOutput = true;
        } else if (args[i] === '--depth' && i + 1 < args.length) {
            depth = args[++i];
        } else if (args[i] === '--workspace' && i + 1 < args.length) {
            workspace = path.resolve(args[++i]);
        } else if (!args[i].startsWith('-')) {
            filePath = args[i];
        }
    }

    if (!filePath) {
        console.error('Usage: securecode-mcp scan <filePath> [--json] [--depth <fast|deep|agent>]');
        process.exit(1);
    }

    const absPath = path.resolve(filePath);
    if (!fs.existsSync(absPath)) {
        console.error(`Error: File not found: ${filePath}`);
        process.exit(1);
    }

    const creds = CredentialStore.getOrThrow();

    const ctx: ServerContext = {
        apiUrl: creds.apiUrl,
        apiToken: creds.apiToken,
        workspaceRoot: workspace,
    };

    // Read the file
    const { readFileFromWorkspace } = require('./utils/files');
    let fileResult;
    try {
        fileResult = readFileFromWorkspace(workspace, filePath);
    } catch (e: any) {
        console.error(`Error: ${e.message}`);
        process.exit(1);
    }

    if (!jsonOutput) {
        console.log(`Scanning: ${filePath}`);
        console.log(`Language: ${fileResult.language}`);
        console.log(`Depth: ${depth}`);
        console.log('');
    }

    try {
        if (depth === 'agent') {
            const { toolAgentScan } = require('./tools/agentScan');
            const result = await toolAgentScan(ctx, {
                filePath,
                _noCache: true,
                _progress: (_p: number, _t: number, msg: string) => {
                    if (!jsonOutput) process.stderr.write(`  ${msg}\r`);
                },
            });

            if (jsonOutput) {
                console.log(JSON.stringify(result, null, 2));
            } else {
                const findings = (result as any).agentFindings || [];
                console.log(`Status: ${(result as any).status}`);
                console.log(`Summary: ${(result as any).summary || 'Scan complete'}`);
                console.log(`Findings: ${findings.length}`);
                console.log(`Steps: ${(result as any).stepsUsed || 0}`);
                console.log(`Cost: $${((result as any).costSpentUsd || 0).toFixed(4)}`);
                console.log('');
                findings.forEach((f: any, i: number) => {
                    const proven = f.proven ? ` [${f.proven}]` : '';
                    console.log(`  [${i + 1}] ${f.type} L${f.line} (${f.severity}, confidence ${f.confidence})${proven}`);
                    console.log(`      ${f.evidence?.slice(0, 100)}...`);
                    if (f.proven === 'PROVEN') console.log(`      PROVEN: ${f.provenReason?.slice(0, 100)}`);
                    console.log('');
                });
            }
            process.exit(findingsCount(result));
        } else {
            const { toolScan } = require('./tools/scan');
            const result = await toolScan(ctx, {
                filePath,
                scanDepth: depth === 'fast' ? 'fast' : 'deep',
            });
            const scanFindings = (result as any).findings || [];
            if (jsonOutput) {
                console.log(JSON.stringify(result, null, 2));
            } else {
                console.log(`Findings: ${scanFindings.length}`);
                scanFindings.forEach((f: any, i: number) => {
                    console.log(`  [${i + 1}] ${f.type} L${f.line} (${f.severity}) — ${f.message?.slice(0, 80)}`);
                });
            }
            process.exit(scanFindings.length > 0 ? 1 : 0);
        }
    } catch (e: any) {
        console.error(`Error: ${e.message}`);
        process.exit(2);
    }
}

function findingsCount(result: any): number {
    return (result.agentFindings || []).length > 0 ? 1 : 0;
}

async function cmdDoctor(): Promise<void> {
    const creds = CredentialStore.get();
    let allOk = true;

    console.log('SecureCode Setup Verification');
    console.log('═══════════════════════════════════════════════════');
    console.log('');

    // 1. Check credentials
    if (!creds) {
        console.log('✗ Credentials: Not authenticated. Run: securecode-mcp login');
        allOk = false;
    } else {
        console.log(`✓ Credentials: Authenticated (token: ${creds.apiToken.substring(0, 8)}...${creds.apiToken.slice(-4)})`);
        console.log(`  API URL: ${creds.apiUrl}`);
    }
    console.log('');

    // 2. Ping /health
    if (creds) {
        try {
            const { ApiClient } = require('./api/client');
            const client = new ApiClient({ baseUrl: creds.apiUrl, token: creds.apiToken });
            // Use a simple GET to /health via fetch
            const response = await fetch(`${creds.apiUrl}/health`);
            if (response.ok) {
                const body = await response.json() as any;
                console.log(`✓ API reachable: ${creds.apiUrl}/health → ${body.status || 'ok'}`);
            } else {
                console.log(`✗ API reachable: HTTP ${response.status}`);
                allOk = false;
            }
        } catch (e: any) {
            console.log(`✗ API reachable: ${e.message}`);
            allOk = false;
        }
    } else {
        console.log('⚠ API reachable: Skipped (no credentials)');
    }
    console.log('');

    // 3. Check workspace
    const workspace = process.cwd();
    const securecodeDir = path.join(workspace, '.securecode');
    if (fs.existsSync(securecodeDir)) {
        console.log(`✓ Workspace: ${workspace} (.securecode/ directory exists)`);
        const memFile = path.join(securecodeDir, 'agent-memory.json');
        if (fs.existsSync(memFile)) {
            try {
                const mem = JSON.parse(fs.readFileSync(memFile, 'utf8'));
                console.log(`  Agent memory: ${mem.falsePositives?.length || 0} false positive(s), ${mem.knownFacts?.length || 0} known fact(s)`);
            } catch {
                console.log('  Agent memory: (corrupt file — will be recreated)');
            }
        } else {
            console.log('  Agent memory: (none yet — created on first dismiss/scan)');
        }
    } else {
        console.log(`✓ Workspace: ${workspace} (.securecode/ will be created on first scan)`);
    }
    console.log('');

    // 4. Check tree-sitter
    try {
        const { parseSource } = require('./project-map/parserLoader');
        const parsed = await parseSource('const x = 1;', 'javascript');
        console.log(`✓ Tree-sitter: ${parsed ? 'working' : 'failed to parse'}`);
        if (!parsed) allOk = false;
    } catch (e: any) {
        console.log(`✗ Tree-sitter: ${e.message}`);
        allOk = false;
    }
    console.log('');

    // Summary
    console.log('═══════════════════════════════════════════════════');
    if (allOk && creds) {
        console.log('All checks passed! You are ready to scan.');
        console.log('');
        console.log('Next steps:');
        console.log('  securecode-mcp scan src/app.ts         # scan a file');
        console.log('  securecode-mcp serve                   # start MCP server');
    } else {
        console.log('Some checks failed. Fix the issues above before scanning.');
        if (!creds) {
            console.log('  Run: securecode-mcp login');
        }
    }
    process.exit(allOk && creds ? 0 : 1);
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
        case 'scan':
            await cmdScan(subArgs);
            break;
        case 'doctor':
            await cmdDoctor();
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
