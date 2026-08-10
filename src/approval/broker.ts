import * as http from 'http';
import * as crypto from 'crypto';
import { exec } from 'child_process';
import { createApprovalRequest, isExpired, type ApprovalRequest, type ApprovalResult } from './types';
import { appendAudit } from './auditLog';

const APPROVAL_PAGE_HTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>SecureCode MCP — Approval Required</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 60px auto; padding: 20px; color: #1a1a1a; }
h1 { font-size: 20px; margin-bottom: 8px; }
.summary { background: #f4f4f4; padding: 16px; border-radius: 8px; margin: 16px 0; font-family: monospace; font-size: 13px; white-space: pre-wrap; word-break: break-all; }
.meta { color: #666; font-size: 13px; margin-bottom: 16px; }
.buttons { display: flex; gap: 12px; margin-top: 24px; }
button { padding: 10px 24px; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; font-weight: 600; }
.approve { background: #16a34a; color: white; }
.deny { background: #dc2626; color: white; }
.result { margin-top: 24px; font-size: 16px; font-weight: 600; }
.timeout { color: #d97706; }
.expired { display: none; color: #dc2626; }
</style>
</head>
<body>
<h1>SecureCode MCP — Approval Required</h1>
<div class="meta">Tool: <span id="tool"></span> | Hash: <span id="hash"></span></div>
<div class="summary" id="summary"></div>
<div class="buttons" id="buttons">
<button class="approve" onclick="respond(true)">Approve</button>
<button class="deny" onclick="respond(false)">Deny</button>
</div>
<div class="result" id="result"></div>
<div class="expired" id="expired">This request has expired. You can close this page.</div>
<script>
const params = new URLSearchParams(window.location.search);
const reqId = params.get('id');
document.getElementById('tool').textContent = params.get('tool') || '';
document.getElementById('hash').textContent = params.get('hash') || '';
document.getElementById('summary').textContent = decodeURIComponent(params.get('summary') || '');

async function respond(approved) {
document.getElementById('buttons').style.display = 'none';
const res = document.getElementById('result');
try {
const r = await fetch('/decide', {
method: 'POST',
headers: {'Content-Type': 'application/json'},
body: JSON.stringify({ id: reqId, approved })
});
const data = await r.json();
if (data.ok) {
res.textContent = approved ? 'Approved. You can close this page.' : 'Denied. You can close this page.';
res.style.color = approved ? '#16a34a' : '#dc2626';
} else {
res.textContent = 'Error: ' + (data.error || 'unknown');
res.style.color = '#dc2626';
}
} catch (e) {
res.textContent = 'Error: ' + e.message;
res.style.color = '#dc2626';
}
}

const expiresAt = parseInt(params.get('exp') || '0');
if (expiresAt && Date.now() > expiresAt) {
document.getElementById('buttons').style.display = 'none';
document.getElementById('expired').style.display = 'block';
}
</script>
</body>
</html>`;

function openBrowser(url: string): void {
    const platform = process.platform;
    try {
        if (platform === 'darwin') {
            exec(`open "${url}"`);
        } else if (platform === 'win32') {
            exec(`start "" "${url}"`);
        } else {
            exec(`xdg-open "${url}"`);
        }
    } catch {
        // If browser open fails, the user can copy the URL from stdout
    }
}

export class ApprovalBroker {
    private server: http.Server | null = null;
    private port = 0;
    private pending: Map<string, { req: ApprovalRequest; resolve: (r: ApprovalResult) => void }> = new Map();

    async start(): Promise<number> {
        return new Promise((resolve) => {
            this.server = http.createServer((req, res) => this.handle(req, res));
            this.server.listen(0, '127.0.0.1', () => {
                const addr = this.server!.address() as any;
                this.port = addr.port;
                resolve(this.port);
            });
        });
    }

    async stop(): Promise<void> {
        return new Promise((resolve) => {
            if (this.server) {
                this.server.close(() => resolve());
            } else {
                resolve();
            }
        });
    }

    getPort(): number {
        return this.port;
    }

    requestApproval(
        tool: string,
        summary: string,
        operationParts: unknown[],
        timeoutMs: number = 60_000,
    ): Promise<ApprovalResult> {
        return new Promise((resolve) => {
            const req = createApprovalRequest(tool, summary, operationParts, timeoutMs);
            const startTime = Date.now();

            this.pending.set(req.id, { req, resolve });

            const url = `http://127.0.0.1:${this.port}/?id=${req.id}&tool=${encodeURIComponent(tool)}&hash=${req.operationHash}&summary=${encodeURIComponent(summary)}&exp=${req.expiresAt}`;
            console.error(`[securecode] Approval required for ${tool}. Open: ${url}`);
            openBrowser(url);

            const timer = setTimeout(() => {
                const entry = this.pending.get(req.id);
                if (entry) {
                    this.pending.delete(req.id);
                    const result: ApprovalResult = {
                        approved: false,
                        reason: 'Request timed out',
                        requestId: req.id,
                        duration: Date.now() - startTime,
                    };
                    appendAudit({
                        timestamp: new Date().toISOString(),
                        requestId: req.id,
                        tool: req.tool,
                        operationHash: req.operationHash,
                        approved: false,
                        reason: 'timeout',
                        durationMs: result.duration,
                    });
                    resolve(result);
                }
            }, timeoutMs + 5000);

            const origResolve = resolve;
            this.pending.set(req.id, {
                req,
                resolve: (r: ApprovalResult) => {
                    clearTimeout(timer);
                    origResolve(r);
                },
            });
        });
    }

    private handle(req: http.IncomingMessage, res: http.ServerResponse): void {
        const url = req.url || '/';

        if (req.method === 'GET' && (url === '/' || url.startsWith('/?'))) {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(APPROVAL_PAGE_HTML);
            return;
        }

        if (req.method === 'POST' && req.url === '/decide') {
            let body = '';
            req.on('data', (c) => { body += c; });
            req.on('end', () => {
                try {
                    const data = JSON.parse(body) as { id?: string; approved?: boolean };
                    const requestId = data.id;
                    const entry = requestId ? this.pending.get(requestId) : undefined;
                    if (!entry || !requestId) {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ ok: false, error: 'Request not found or already answered' }));
                        return;
                    }

                    if (isExpired(entry.req)) {
                        this.pending.delete(requestId);
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ ok: false, error: 'Request expired' }));
                        return;
                    }

                    this.pending.delete(requestId);
                    const approved = data.approved === true;
                    const startTime = entry.req.createdAt;
                    const result: ApprovalResult = {
                        approved,
                        reason: approved ? 'User approved' : 'User denied',
                        requestId: entry.req.id,
                        duration: Date.now() - startTime,
                    };

                    appendAudit({
                        timestamp: new Date().toISOString(),
                        requestId: entry.req.id,
                        tool: entry.req.tool,
                        operationHash: entry.req.operationHash,
                        approved,
                        reason: approved ? 'approved' : 'denied',
                        durationMs: result.duration,
                    });

                    entry.resolve(result);

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ ok: true }));
                } catch {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ ok: false, error: 'Invalid request body' }));
                }
            });
            return;
        }

        res.writeHead(404);
        res.end('Not found');
    }
}
