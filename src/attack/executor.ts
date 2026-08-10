import * as http from 'http';
import * as https from 'https';
import type { AttackBudget } from './policy';
import { isRedirectToNonLocal } from './policy';

export interface ExecRequest {
    method: string;
    path: string;
    host: string;
    port: number;
    headers?: Record<string, string>;
    body?: unknown;
}

export interface ExecResponse {
    statusCode: number;
    headers: Record<string, string>;
    body: string;
    latencyMs: number;
    error?: string;
}

export async function executeHttpRequest(
    req: ExecRequest,
    budget: AttackBudget,
    signal?: AbortSignal,
): Promise<ExecResponse> {
    const startTime = Date.now();

    return new Promise<ExecResponse>((resolve) => {
        const bodyData = req.body ? JSON.stringify(req.body) : undefined;
        const isHttps = false; // localhost only, HTTP by default
        const lib = isHttps ? https : http;

        const requestOptions: http.RequestOptions = {
            hostname: req.host,
            port: req.port,
            path: req.path,
            method: req.method,
            headers: {
                ...(req.headers || {}),
                ...(bodyData ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyData) } : {}),
            },
            timeout: budget.requestTimeoutMs,
        };

        const onRequest = (res: http.IncomingMessage) => {
            if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400) {
                const location = res.headers.location;
                if (isRedirectToNonLocal(res.statusCode, location)) {
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers as Record<string, string>,
                        body: '',
                        latencyMs: Date.now() - startTime,
                        error: `Redirect to non-localhost blocked: ${location}`,
                    });
                    res.destroy();
                    return;
                }
            }

            let body = '';
            let aborted = false;
            let totalBytes = 0;

            res.on('data', (chunk: Buffer) => {
                totalBytes += chunk.length;
                if (totalBytes > budget.maxResponseBytes) {
                    aborted = true;
                    res.destroy();
                    resolve({
                        statusCode: res.statusCode || 0,
                        headers: res.headers as Record<string, string>,
                        body: body + chunk.toString('utf8').slice(0, budget.maxResponseBytes - body.length),
                        latencyMs: Date.now() - startTime,
                        error: `Response exceeded ${budget.maxResponseBytes} bytes`,
                    });
                    return;
                }
                body += chunk.toString('utf8');
            });

            res.on('end', () => {
                if (aborted) return;
                resolve({
                    statusCode: res.statusCode || 0,
                    headers: res.headers as Record<string, string>,
                    body,
                    latencyMs: Date.now() - startTime,
                });
            });

            res.on('error', (err) => {
                if (aborted) return;
                resolve({
                    statusCode: 0,
                    headers: {},
                    body: '',
                    latencyMs: Date.now() - startTime,
                    error: err.message,
                });
            });
        };

        const request = lib.request(requestOptions, onRequest);

        request.on('error', (err) => {
            resolve({
                statusCode: 0,
                headers: {},
                body: '',
                latencyMs: Date.now() - startTime,
                error: err.message,
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                statusCode: 0,
                headers: {},
                body: '',
                latencyMs: Date.now() - startTime,
                error: `Request timed out after ${budget.requestTimeoutMs}ms`,
            });
        });

        if (signal) {
            if (signal.aborted) {
                request.destroy();
                resolve({
                    statusCode: 0,
                    headers: {},
                    body: '',
                    latencyMs: Date.now() - startTime,
                    error: 'Cancelled by abort signal',
                });
                return;
            }
            signal.addEventListener('abort', () => {
                request.destroy();
                resolve({
                    statusCode: 0,
                    headers: {},
                    body: '',
                    latencyMs: Date.now() - startTime,
                    error: 'Cancelled by abort signal',
                });
            });
        }

        if (bodyData) {
            request.write(bodyData);
        }
        request.end();
    });
}
