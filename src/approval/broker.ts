import * as http from 'http';
import { exec } from 'child_process';
import {
    createApprovalRequest,
    isExpired,
    type ApprovalRequest,
    type ApprovalResult,
    type AuditEntry,
    type AuditReason,
    type OperationCategory,
} from './types';
import { appendAudit } from './auditLog';

const MAX_PENDING = 16;
const MAX_BODY_BYTES = 4096;
const LOOPBACK = '127.0.0.1';

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
.error { color: #dc2626; }
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
let decisionToken = '';

async function loadDetails() {
    try {
        const r = await fetch('/details?id=' + encodeURIComponent(reqId || ''));
        const data = await r.json();
        if (!data.ok) {
            document.getElementById('buttons').style.display = 'none';
            const el = document.getElementById('result');
            el.textContent = 'Error: ' + (data.error || 'unknown');
            el.style.color = '#dc2626';
            return;
        }
        document.getElementById('tool').textContent = data.tool || '';
        document.getElementById('hash').textContent = data.operationHash || '';
        document.getElementById('summary').textContent = data.summary || '';
        decisionToken = data.decisionToken || '';
        if (data.expiresAt && Date.now() > data.expiresAt) {
            document.getElementById('buttons').style.display = 'none';
            document.getElementById('expired').style.display = 'block';
        }
    } catch (e) {
        document.getElementById('buttons').style.display = 'none';
        const el = document.getElementById('result');
        el.textContent = 'Error loading details: ' + e.message;
        el.style.color = '#dc2626';
    }
}

async function respond(approved) {
    document.getElementById('buttons').style.display = 'none';
    const res = document.getElementById('result');
    try {
        const r = await fetch('/decide', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ id: reqId, decisionToken, approved })
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

loadDetails();
</script>
</body>
</html>`;

function openBrowser(url: string): void {
    if (process.env.SECURECODE_TEST_MODE === '1') return;
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

interface PendingEntry {
    req: ApprovalRequest;
    resolve: (r: ApprovalResult) => void;
    timer: ReturnType<typeof setTimeout>;
    settled: boolean;
}

const SECURITY_HEADERS: Record<string, string> = {
    'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
};

export class ApprovalBroker {
    private server: http.Server | null = null;
    private port = 0;
    private pending: Map<string, PendingEntry> = new Map();

    async start(): Promise<number> {
        return new Promise<number>((resolve, reject) => {
            this.server = http.createServer((req, res) => this.handle(req, res));
            this.server.once('error', (err) => {
                reject(err);
            });
            this.server.listen(0, LOOPBACK, () => {
                const addr = this.server!.address() as any;
                this.port = addr.port;
                resolve(this.port);
            });
        });
    }

    async stop(): Promise<void> {
        for (const [, entry] of this.pending) {
            this.settle(entry, false, 'shutdown', 'Broker shutting down');
        }
        return new Promise<void>((resolve) => {
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
        category: OperationCategory = 'paid-generation',
        workspaceRoot: string | null = null,
    ): Promise<ApprovalResult> {
        return new Promise<ApprovalResult>((resolve) => {
            if (this.pending.size >= MAX_PENDING) {
                resolve({
                    approved: false,
                    reason: 'Too many pending approval requests',
                    requestId: '',
                    duration: 0,
                    category,
                });
                return;
            }

            const req = createApprovalRequest(tool, summary, operationParts, timeoutMs, category, workspaceRoot);
            const startTime = req.createdAt;

            const timer = setTimeout(() => {
                const entry = this.pending.get(req.id);
                if (entry && !entry.settled) {
                    this.settle(entry, false, 'timeout', 'Request timed out');
                }
            }, timeoutMs + 5000);

            const entry: PendingEntry = { req, resolve, timer, settled: false };
            this.pending.set(req.id, entry);

            const url = `http://${LOOPBACK}:${this.port}/?id=${req.id}`;
            console.error(`[securecode] Approval required for ${tool}. Open: ${url}`);
            openBrowser(url);
        });
    }

    private settle(
        entry: PendingEntry,
        approved: boolean,
        reason: AuditReason,
        humanReason: string,
    ): void {
        if (entry.settled) return;
        entry.settled = true;
        clearTimeout(entry.timer);
        this.pending.delete(entry.req.id);

        const duration = Date.now() - entry.req.createdAt;
        const result: ApprovalResult = {
            approved,
            reason: humanReason,
            requestId: entry.req.id,
            duration,
            category: entry.req.category,
        };

        const audit: AuditEntry = {
            timestamp: new Date().toISOString(),
            requestId: entry.req.id,
            tool: entry.req.tool,
            operationHash: entry.req.operationHash,
            category: entry.req.category,
            workspaceId: entry.req.workspaceId,
            approved,
            reason,
            durationMs: duration,
        };
        appendAudit(audit);

        entry.resolve(result);
    }

    private isLocalOrigin(req: http.IncomingMessage): boolean {
        const origin = req.headers.origin;
        if (!origin) return true; // non-browser client
        try {
            const u = new URL(origin);
            return u.hostname === LOOPBACK;
        } catch {
            return false;
        }
    }

    private isLocalHost(req: http.IncomingMessage): boolean {
        const host = req.headers.host || '';
        try {
            const { hostname } = new URL(`http://${host}`);
            return hostname === LOOPBACK || hostname === 'localhost';
        } catch {
            return false;
        }
    }

    private handle(req: http.IncomingMessage, res: http.ServerResponse): void {
        if (!this.isLocalHost(req)) {
            res.writeHead(403, SECURITY_HEADERS);
            res.end('Forbidden');
            return;
        }

        const url = req.url || '/';

        if (req.method === 'GET' && (url === '/' || url.startsWith('/?'))) {
            res.writeHead(200, { 'Content-Type': 'text/html', ...SECURITY_HEADERS });
            res.end(APPROVAL_PAGE_HTML);
            return;
        }

        if (req.method === 'GET' && url.startsWith('/details')) {
            this.handleDetails(req, res);
            return;
        }

        if (req.method === 'POST' && req.url === '/decide') {
            this.handleDecide(req, res);
            return;
        }

        res.writeHead(404, SECURITY_HEADERS);
        res.end('Not found');
    }

    private handleDetails(req: http.IncomingMessage, res: http.ServerResponse): void {
        const parsed = new URL(req.url || '', `http://${LOOPBACK}`);
        const id = parsed.searchParams.get('id');
        const entry = id ? this.pending.get(id) : undefined;

        if (!entry || !id) {
            res.writeHead(200, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
            res.end(JSON.stringify({ ok: false, error: 'Request not found or already answered' }));
            return;
        }

        if (isExpired(entry.req)) {
            res.writeHead(200, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
            res.end(JSON.stringify({ ok: false, error: 'Request expired' }));
            return;
        }

        res.writeHead(200, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
        res.end(JSON.stringify({
            ok: true,
            tool: entry.req.tool,
            summary: entry.req.summary,
            operationHash: entry.req.operationHash,
            expiresAt: entry.req.expiresAt,
            decisionToken: entry.req.decisionToken,
        }));
    }

    private handleDecide(req: http.IncomingMessage, res: http.ServerResponse): void {
        if (!this.isLocalOrigin(req)) {
            res.writeHead(403, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
            res.end(JSON.stringify({ ok: false, error: 'Forbidden origin' }));
            return;
        }

        const ct = req.headers['content-type'] || '';
        if (!ct.includes('application/json')) {
            res.writeHead(400, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
            res.end(JSON.stringify({ ok: false, error: 'Content-Type must be application/json' }));
            return;
        }

        let body = '';
        let tooLarge = false;
        req.on('data', (c) => {
            body += c;
            if (body.length > MAX_BODY_BYTES) {
                tooLarge = true;
                req.destroy();
            }
        });
        req.on('end', () => {
            if (tooLarge) {
                res.writeHead(413, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
                res.end(JSON.stringify({ ok: false, error: 'Body too large' }));
                return;
            }
            try {
                const data = JSON.parse(body) as { id?: string; decisionToken?: string; approved?: boolean };
                const requestId = data.id;
                const entry = requestId ? this.pending.get(requestId) : undefined;

                if (!entry || !requestId) {
                    res.writeHead(200, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
                    res.end(JSON.stringify({ ok: false, error: 'Request not found or already answered' }));
                    return;
                }

                if (entry.settled) {
                    res.writeHead(200, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
                    res.end(JSON.stringify({ ok: false, error: 'Request already answered' }));
                    return;
                }

                if (!data.decisionToken || data.decisionToken !== entry.req.decisionToken) {
                    this.settle(entry, false, 'invalid-token', 'Invalid decision token');
                    res.writeHead(200, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
                    res.end(JSON.stringify({ ok: false, error: 'Invalid decision token' }));
                    return;
                }

                if (isExpired(entry.req)) {
                    this.settle(entry, false, 'expired', 'Request expired');
                    res.writeHead(200, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
                    res.end(JSON.stringify({ ok: false, error: 'Request expired' }));
                    return;
                }

                const approved = data.approved === true;
                this.settle(entry, approved, approved ? 'approved' : 'denied', approved ? 'User approved' : 'User denied');

                res.writeHead(200, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
                res.end(JSON.stringify({ ok: true }));
            } catch {
                res.writeHead(400, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
                res.end(JSON.stringify({ ok: false, error: 'Invalid request body' }));
            }
        });
    }
}
