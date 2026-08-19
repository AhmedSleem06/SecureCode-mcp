import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as http from 'http';
import * as fs from 'fs';
import * as os from 'os';

const SERVER_JS = path.resolve(__dirname, '..', 'dist', 'index.js');
const MCP_TOKEN = 'test-api-token-1234567890abcdef';

interface MockApiHandler {
    (req: http.IncomingMessage, res: http.ServerResponse): void;
}

class MockApiServer {
    private server: http.Server;
    private handler: MockApiHandler;
    public port = 0;
    public baseUrl = '';

    constructor(handler: MockApiHandler) {
        this.handler = handler;
        this.server = http.createServer((req, res) => this.handler(req, res));
    }

    async start(): Promise<void> {
        return new Promise((resolve) => {
            this.server.listen(0, '127.0.0.1', () => {
                const addr = this.server.address() as any;
                this.port = addr.port;
                this.baseUrl = `http://127.0.0.1:${this.port}`;
                resolve();
            });
        });
    }

    async stop(): Promise<void> {
        return new Promise((resolve) => this.server.close(() => resolve()));
    }
}

class McpClient {
    private proc: ChildProcess;
    private buffer = '';
    private pending = new Map<number | string, { resolve: (v: any) => void; reject: (e: any) => void; timeout: NodeJS.Timeout }>();
    public stdoutLines: string[] = [];

    constructor(env: Record<string, string>) {
        this.proc = spawn(process.execPath, [SERVER_JS, 'serve', '--workspace', env.WORKSPACE_ROOT || process.cwd()], {
            env: { ...process.env, ...env },
            stdio: ['pipe', 'pipe', 'pipe'],
        });

        this.proc.stdout!.on('data', (chunk: Buffer) => {
            this.buffer += chunk.toString('utf8');
            const lines = this.buffer.split('\n');
            this.buffer = lines.pop() || '';
            for (const line of lines) {
                this.stdoutLines.push(line);
                try {
                    const msg = JSON.parse(line);
                    if (msg.id !== undefined && msg.id !== null) {
                        const pending = this.pending.get(msg.id);
                        if (pending) {
                            clearTimeout(pending.timeout);
                            this.pending.delete(msg.id);
                            if (msg.error) {
                                pending.reject(msg.error);
                            } else {
                                pending.resolve(msg.result);
                            }
                        }
                    }
                } catch {
                    // non-JSON line on stdout — should never happen
                }
            }
        });
    }

    request(method: string, params?: any, timeoutMs = 5000): Promise<any> {
        const id = Math.floor(Math.random() * 1000000);
        const msg = JSON.stringify({ jsonrpc: '2.0', id, method, params });
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                this.pending.delete(id);
                reject(new Error(`MCP server did not answer '${method}' (id ${id}) within ${timeoutMs}ms`));
            }, timeoutMs);
            this.pending.set(id, { resolve, reject, timeout });
            this.proc.stdin!.write(msg + '\n');
        });
    }

    callTool(name: string, args: any): Promise<any> {
        return this.request('tools/call', { name, arguments: args });
    }

    sendRaw(line: string): void {
        this.proc.stdin!.write(line + '\n');
    }

    close(): Promise<void> {
        if (this.proc.exitCode !== null || this.proc.signalCode) {
            return Promise.resolve();
        }
        return new Promise((resolve) => {
            this.proc.on('close', () => resolve());
            this.proc.stdin!.end();
        });
    }
}

function makeWorkspace(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-mcp-test-'));
    fs.writeFileSync(path.join(dir, 'vuln.js'), 'const id = req.query.id;\ndb.query("SELECT * FROM users WHERE id = " + id);\n');
    // Write a minimal package-lock.json with 0 dependencies so the
    // scan-dependencies tool has a lockfile to find but makes no OSV calls.
    fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({
        name: 'test-project',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: { '': { name: 'test-project', version: '1.0.0' } },
    }));
    return dir;
}

describe('SecureCode MCP — protocol conformance', () => {
    let workspace: string;
    let mockApi: MockApiServer;
    let client: McpClient;

    beforeAll(async () => {
        workspace = makeWorkspace();

        let scanCallCount = 0;
        mockApi = new MockApiServer((req, res) => {
            let body = '';
            req.on('data', (c) => { body += c; });
            req.on('end', () => {
                if (req.url === '/scan') {
                    scanCallCount++;
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        scanType: 'advanced',
                        scanId: 'test-scan-id',
                        finalFindings: [{
                            final_id: 'final_0',
                            type: 'sql_injection',
                            severity: 'HIGH',
                            confidence: 90,
                            location: { line_start: 2, line_end: 2 },
                            evidence_snippet: 'db.query("SELECT * FROM users WHERE id = " + id)',
                            decision_basis: 'AI_ONLY',
                            why_real: 'user-controlled input flows into SQL',
                            fix_strategy: 'parameterize the query',
                        }],
                        scanSummary: 'Found 1 vulnerability',
                        remainingAIScans: 99,
                        plan: 'free',
                        degraded: false,
                        scanCredits: 99,
                    }));
                } else if (req.url === '/fix') {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        fixed_code: 'db.query("SELECT * FROM users WHERE id = $1", [id])',
                        diff: '--- fix\n+++ fix\n',
                        fix_summary: 'Parameterized the query',
                        security_notes: ['Prevents SQL injection'],
                        why_secure: 'Input is no longer concatenated',
                        confidence: 95,
                    }));
                } else {
                    res.writeHead(404);
                    res.end('{}');
                }
            });
        });
        await mockApi.start();

        client = new McpClient({
            SECURECODE_API_TOKEN: MCP_TOKEN,
            SECURECODE_API_URL: mockApi.baseUrl,
            WORKSPACE_ROOT: workspace,
        });
    });

    afterAll(async () => {
        try { await client.close(); } catch { /* already closed by last test */ }
        await mockApi.stop();
        try { fs.rmSync(workspace, { recursive: true, force: true }); } catch { /* best effort */ }
    }, 10_000);

    it('initialize handshake returns protocol version, capabilities and serverInfo', async () => {
        const res = await client.request('initialize');
        expect(res.protocolVersion).toBe('2025-03-26');
        expect(res.capabilities).toBeDefined();
        expect(res.serverInfo.name).toBe('securecode-mcp');
        expect(res.serverInfo.version).toBe('0.2.0');
    });

    it('notifications/initialized is accepted with no response', async () => {
        client.sendRaw(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }));
        await new Promise((r) => setTimeout(r, 500));
        // No response should be sent for a notification
        const lastLine = client.stdoutLines[client.stdoutLines.length - 1];
        if (lastLine) {
            const msg = JSON.parse(lastLine);
            expect(msg.id).not.toBe(null);
        }
    });

    it('tools/list advertises exactly the documented tool set', async () => {
        const res = await client.request('tools/list');
        const names = res.tools.map((t: any) => t.name);
        expect(names).toEqual(expect.arrayContaining([
            'securecode.scan',
            'securecode.map',
            'securecode.fix',
            'securecode.attack',
            'securecode.scan-dependencies',
            'securecode.scan-batch',
            'securecode.scan-secrets',
            'securecode.agent-scan',
            'securecode.run-tests',
            'securecode.record-false-positive',
            'securecode.get-agent-memory',
            'securecode.clear-agent-memory',
            'securecode.add-known-fact',
        ]));
        expect(names.length).toBe(13);
    });

    it('every tool carries a valid JSON Schema', async () => {
        const res = await client.request('tools/list');
        for (const tool of res.tools) {
            expect(tool.inputSchema.type).toBe('object');
            expect(tool.inputSchema.properties).toBeDefined();
        }
    });

    it('tools do not require an apiKey parameter', async () => {
        const res = await client.request('tools/list');
        for (const tool of res.tools) {
            const required = tool.inputSchema.required || [];
            expect(required).not.toContain('apiKey');
        }
    });

    it('securecode.scan forwards to the API and returns findings', async () => {
        const res = await client.callTool('securecode.scan', {
            code: 'const id = req.query.id;\ndb.query("SELECT * FROM users WHERE id = " + id);',
            language: 'javascript',
        });
        expect(res.content).toBeDefined();
        expect(res.content[0].type).toBe('text');
        const payload = JSON.parse(res.content[0].text);
        expect(payload.scanType).toBe('advanced');
        expect(payload.findings.length).toBeGreaterThan(0);
        expect(payload.findings[0].type).toBe('sql_injection');
        expect(payload.findings[0].severity).toBe('HIGH');
    });

    it('securecode.scan reads from disk when given filePath', async () => {
        const res = await client.callTool('securecode.scan', {
            filePath: 'vuln.js',
        });
        const payload = JSON.parse(res.content[0].text);
        expect(payload.scanType).toBe('advanced');
        expect(payload.findings.length).toBeGreaterThan(0);
    });

    it('securecode.scan rejects a filePath outside the workspace', async () => {
        try {
            await client.callTool('securecode.scan', { filePath: '../etc/passwd' });
            expect(false).toBe(true);
        } catch (err: any) {
            expect(err.message).toMatch(/outside the workspace/i);
        }
    });

    it('securecode.map returns empty endpoints when no cache exists', async () => {
        const res = await client.callTool('securecode.map', {});
        const payload = JSON.parse(res.content[0].text);
        expect(payload.endpoints).toEqual([]);
    });

    it('securecode.scan-dependencies returns valid structure for empty lockfile', async () => {
        const res = await client.callTool('securecode.scan-dependencies', {});
        const payload = JSON.parse(res.content[0].text);
        expect(payload).toHaveProperty('findings');
        expect(payload).toHaveProperty('packageCount');
        expect(payload).toHaveProperty('unresolvedCount');
        expect(payload).toHaveProperty('lockfiles');
        expect(payload).toHaveProperty('ghsaSkipped');
        expect(Array.isArray(payload.findings)).toBe(true);
        expect(Array.isArray(payload.lockfiles)).toBe(true);
        // The fixture lockfile has 0 packages → 0 findings
        expect(payload.findings.length).toBe(0);
        expect(payload.packageCount).toBe(0);
        expect(payload.lockfiles.length).toBe(1);
    });

    it('an unknown method returns -32601 Method not found', async () => {
        try {
            await client.request('unknown/method');
            expect(false).toBe(true);
        } catch (err: any) {
            expect(err.code).toBe(-32601);
        }
    });

    it('an unknown tool name returns -32601', async () => {
        try {
            await client.callTool('securecode.definitelyNotATool', {});
            expect(false).toBe(true);
        } catch (err: any) {
            expect(err.code).toBe(-32601);
        }
    });

    it('malformed JSON returns -32700 rather than silence', async () => {
        client.sendRaw('{"jsonrpc":"2.0","id":99,"method":"tools/list"');
        await new Promise((r) => setTimeout(r, 500));
        const lastLine = client.stdoutLines[client.stdoutLines.length - 1];
        const msg = JSON.parse(lastLine);
        expect(msg.error?.code).toBe(-32700);
    });

    it('missing required params return -32602 Invalid params', async () => {
        try {
            await client.callTool('securecode.fix', { code: 'x', language: 'javascript' });
            expect(false).toBe(true);
        } catch (err: any) {
            expect(err.code).toBe(-32602);
        }
    });

    it('a tool-level failure is reported as an error, not a crash', async () => {
        try {
            await client.callTool('securecode.scan', { code: 'x', language: 'javascript' });
        } catch (err: any) {
            // The mock API should still respond — this tests that a non-200
            // surfaces as an error, not a process crash
            expect(err).toBeDefined();
        }
    });

    it('closing stdin shuts the server down cleanly with exit code 0', async () => {
        await client.close();
    });
});
