#!/usr/bin/env node

import * as path from 'path';
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
