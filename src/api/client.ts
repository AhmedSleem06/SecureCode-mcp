import * as http from 'http';
import * as https from 'https';
import type { ApiError, ApiErrorDetails } from './types';

const DEFAULT_TIMEOUT_MS = 1_200_000;
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

export class ApiClientError extends Error {
    public readonly creditType: string | undefined;
    public readonly requested: number | undefined;
    public readonly balance: number | undefined;
    public readonly required: number | undefined;
    public readonly available: number | undefined;
    public readonly retryable: boolean | undefined;

    constructor(
        public readonly status: number,
        public readonly apiCode: string | undefined,
        message: string,
        public readonly remaining: number | undefined,
        details?: ApiErrorDetails,
    ) {
        super(message);
        this.name = 'ApiClientError';
        this.creditType = details?.creditType;
        this.requested = details?.requested;
        this.balance = details?.balance;
        this.required = details?.required;
        this.available = details?.available;
        this.retryable = details?.retryable;
    }

    static isInsufficientCredits(err: unknown): boolean {
        return err instanceof ApiClientError && err.status === 402;
    }

    static isAuthFailure(err: unknown): boolean {
        return err instanceof ApiClientError && err.status === 401;
    }

    static isRateLimit(err: unknown): boolean {
        return err instanceof ApiClientError && err.status === 429;
    }

    static isServerUnavailable(err: unknown): boolean {
        return err instanceof ApiClientError && err.status === 503;
    }

    static isAgentScanConflict(err: unknown): boolean {
        return err instanceof ApiClientError &&
            (err.status === 409 || err.apiCode === 'AGENT_SCAN_ALREADY_RUNNING');
    }

    static isCreditLockTimeout(err: unknown): boolean {
        return err instanceof ApiClientError &&
            err.apiCode === 'CREDIT_LOCK_TIMEOUT';
    }
}

export interface ApiClientOptions {
    baseUrl: string;
    token: string;
    timeoutMs?: number;
}

export class ApiClient {
    private readonly baseUrl: string;
    private readonly token: string;
    private readonly timeoutMs: number;

    constructor(opts: ApiClientOptions) {
        this.baseUrl = opts.baseUrl.replace(/\/$/, '');
        this.token = opts.token;
        this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    }

    async postJson<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
        const url = `${this.baseUrl}${path}`;
        const payload = JSON.stringify(body);
        const parsed = new URL(url);
        const lib = parsed.protocol === 'https:' ? https : http;

        return new Promise<T>((resolve, reject) => {
            const req = lib.request(
                {
                    hostname: parsed.hostname,
                    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
                    path: parsed.pathname + parsed.search,
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(payload),
                        Authorization: `Bearer ${this.token}`,
                    },
                    signal,  // AbortSignal — when aborted, the request is destroyed
                },
                (res) => {
                    let raw = '';
                    let aborted = false;
                    res.on('data', (chunk: Buffer) => {
                        if (raw.length + chunk.length > MAX_RESPONSE_BYTES) {
                            aborted = true;
                            req.destroy();
                            reject(new ApiClientError(502, undefined, 'Response too large', undefined));
                            return;
                        }
                        raw += chunk.toString('utf8');
                    });
                    res.on('end', () => {
                        if (aborted) return;
                        let data: any;
                        try {
                            data = raw ? JSON.parse(raw) : {};
                        } catch {
                            data = { raw };
                        }
                        const status = res.statusCode ?? 0;
                        if (status >= 200 && status < 300) {
                            resolve(data as T);
                        } else {
                            const details: ApiErrorDetails = {
                                creditType: data.creditType,
                                requested: data.requested,
                                balance: data.balance,
                                required: data.required,
                                available: data.available,
                                retryable: data.retryable,
                            };
                            reject(new ApiClientError(
                                status,
                                data.code || data.error_code,
                                data.error || data.message || `HTTP ${status}`,
                                data.remaining,
                                details,
                            ));
                        }
                    });
                },
            );

            req.on('error', (err) => {
                reject(new ApiClientError(0, undefined, `Network error: ${err.message}`, undefined));
            });

            req.setTimeout(this.timeoutMs, () => {
                req.destroy();
                reject(new ApiClientError(0, undefined, `Request timed out after ${this.timeoutMs}ms`, undefined));
            });

            req.write(payload);
            req.end();
        });
    }

    async getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
        const url = `${this.baseUrl}${path}`;
        const parsed = new URL(url);
        const lib = parsed.protocol === 'https:' ? https : http;

        return new Promise<T>((resolve, reject) => {
            const req = lib.request(
                {
                    hostname: parsed.hostname,
                    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
                    path: parsed.pathname + parsed.search,
                    method: 'GET',
                    headers: {
                        Authorization: `Bearer ${this.token}`,
                    },
                    signal,
                },
                (res) => {
                    let raw = '';
                    let aborted = false;
                    res.on('data', (chunk: Buffer) => {
                        if (raw.length + chunk.length > MAX_RESPONSE_BYTES) {
                            aborted = true;
                            req.destroy();
                            reject(new ApiClientError(502, undefined, 'Response too large', undefined));
                            return;
                        }
                        raw += chunk.toString('utf8');
                    });
                    res.on('end', () => {
                        if (aborted) return;
                        let data: any;
                        try {
                            data = raw ? JSON.parse(raw) : {};
                        } catch {
                            data = { raw };
                        }
                        const status = res.statusCode ?? 0;
                        if (status >= 200 && status < 300) {
                            resolve(data as T);
                        } else {
                            const details: ApiErrorDetails = {
                                creditType: data.creditType,
                                requested: data.requested,
                                balance: data.balance,
                                required: data.required,
                                available: data.available,
                                retryable: data.retryable,
                            };
                            reject(new ApiClientError(
                                status,
                                data.code || data.error_code,
                                data.error || data.message || `HTTP ${status}`,
                                data.remaining,
                                details,
                            ));
                        }
                    });
                },
            );

            req.on('error', (err) => {
                reject(new ApiClientError(0, undefined, `Network error: ${err.message}`, undefined));
            });

            req.setTimeout(this.timeoutMs, () => {
                req.destroy();
                reject(new ApiClientError(0, undefined, `Request timed out after ${this.timeoutMs}ms`, undefined));
            });

            req.end();
        });
    }

    /**
     * POST without an Authorization header — for login/OTP before a token exists.
     */
    static async postJsonNoAuth(baseUrl: string, path: string, body: unknown, timeoutMs = 30_000): Promise<any> {
        const url = `${baseUrl.replace(/\/$/, '')}${path}`;
        const payload = JSON.stringify(body);
        const parsed = new URL(url);
        const lib = parsed.protocol === 'https:' ? https : http;

        return new Promise<any>((resolve, reject) => {
            const req = lib.request(
                {
                    hostname: parsed.hostname,
                    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
                    path: parsed.pathname + parsed.search,
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(payload),
                    },
                },
                (res) => {
                    let raw = '';
                    res.on('data', (chunk: Buffer) => { raw += chunk.toString('utf8'); });
                    res.on('end', () => {
                        let data: any;
                        try { data = raw ? JSON.parse(raw) : {}; } catch { data = { raw }; }
                        const status = res.statusCode ?? 0;
                        if (status >= 200 && status < 300) {
                            resolve(data);
                        } else {
                            reject(new ApiClientError(
                                status,
                                data.code,
                                data.error || data.message || `HTTP ${status}`,
                                data.remaining,
                            ));
                        }
                    });
                },
            );
            req.on('error', (err) => {
                reject(new ApiClientError(0, undefined, `Network error: ${err.message}`, undefined));
            });
            req.setTimeout(timeoutMs, () => {
                req.destroy();
                reject(new ApiClientError(0, undefined, `Request timed out after ${timeoutMs}ms`, undefined));
            });
            req.write(payload);
            req.end();
        });
    }
}
