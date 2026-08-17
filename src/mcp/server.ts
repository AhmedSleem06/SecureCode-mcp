import * as readline from 'readline';
import type { JsonRpcRequest, JsonRpcResponse, ToolDef, ServerContext } from './types';
import { TOOLS } from './tools';
import { toolScan } from '../tools/scan';
import { toolMap } from '../tools/map';
import { toolFix } from '../tools/fix';
import { toolAttack } from '../tools/attack';
import { toolScanDependencies } from '../tools/scanDependencies';
import { toolScanBatch } from '../tools/scanBatch';
import { toolScanSecrets } from '../tools/scanSecrets';
import { toolAgentScan } from '../tools/agentScan';
import { toolRecordFalsePositive, toolGetAgentMemory, toolClearAgentMemory, toolAddKnownFact } from '../tools/agentMemoryTools';

const PROTOCOL_VERSION = '2025-03-26';
const SERVER_NAME = 'securecode-mcp';
const SERVER_VERSION = '0.2.0';

let initialized = false;

function send(msg: JsonRpcResponse | { jsonrpc: '2.0'; method: string; params?: unknown }): void {
    process.stdout.write(JSON.stringify(msg) + '\n');
}

function result(id: number | string | null, value: unknown): void {
    send({ jsonrpc: '2.0', id, result: value });
}

function error(id: number | string | null, code: number, message: string, data?: unknown): void {
    send({ jsonrpc: '2.0', id, error: { code, message, data } });
}

/** Send a progress notification so the MCP client knows the server is still working. */
function sendProgress(progressToken: string | number | undefined, progress: number, total: number, message: string): void {
    if (progressToken === undefined) return;
    send({
        jsonrpc: '2.0',
        method: 'notifications/progress',
        params: { progressToken, progress, total, message },
    });
}

const TOOL_HANDLERS: Record<string, (ctx: ServerContext, args: any) => Promise<unknown>> = {
    'securecode.scan': toolScan,
    'securecode.map': toolMap,
    'securecode.fix': toolFix,
    'securecode.attack': toolAttack,
    'securecode.scan-dependencies': toolScanDependencies,
    'securecode.scan-batch': toolScanBatch,
    'securecode.scan-secrets': toolScanSecrets,
    'securecode.agent-scan': toolAgentScan,
    'securecode.record-false-positive': toolRecordFalsePositive,
    'securecode.get-agent-memory': toolGetAgentMemory,
    'securecode.clear-agent-memory': toolClearAgentMemory,
    'securecode.add-known-fact': toolAddKnownFact,
};

function validateArgs(tool: ToolDef, args: any): string | null {
    const schema = tool.inputSchema as {
        properties?: Record<string, { type?: string }>;
        required?: string[];
    };
    const props = schema.properties || {};
    for (const name of schema.required || []) {
        if (args[name] === undefined || args[name] === null) {
            return `Missing required parameter '${name}' for ${tool.name}.`;
        }
    }
    for (const [name, value] of Object.entries(args)) {
        const declared = props[name]?.type;
        if (!declared || value === undefined || value === null) continue;
        const ok =
            declared === 'string' ? typeof value === 'string' :
            declared === 'number' ? typeof value === 'number' && Number.isFinite(value) :
            declared === 'boolean' ? typeof value === 'boolean' :
            declared === 'object' ? typeof value === 'object' && !Array.isArray(value) :
            declared === 'array' ? Array.isArray(value) :
            true;
        if (!ok) {
            return `Parameter '${name}' of ${tool.name} must be a ${declared}, got ${Array.isArray(value) ? 'array' : typeof value}.`;
        }
    }
    return null;
}

async function handleRequest(ctx: ServerContext, req: JsonRpcRequest): Promise<JsonRpcResponse> {
    const id = req.id ?? null;
    try {
        switch (req.method) {
            case 'initialize': {
                initialized = true;
                return {
                    jsonrpc: '2.0', id,
                    result: {
                        protocolVersion: PROTOCOL_VERSION,
                        capabilities: { tools: { listChanged: false } },
                        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
                    },
                };
            }
            case 'notifications/initialized': {
                return { jsonrpc: '2.0', id: null };
            }
            case 'tools/list': {
                return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
            }
            case 'tools/call': {
                const params = (req.params || {}) as { name?: string; arguments?: any; _meta?: { progressToken?: string | number } };
                const name = params.name;
                const args = params.arguments || {};
                const progressToken = params._meta?.progressToken;
                const handler = name ? TOOL_HANDLERS[name] : undefined;
                if (!handler) {
                    return { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${name}` } };
                }
                const toolDef = TOOLS.find((t) => t.name === name);
                if (!toolDef) {
                    return { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${name}` } };
                }
                const invalid = validateArgs(toolDef, args);
                if (invalid) {
                    return { jsonrpc: '2.0', id, error: { code: -32602, message: invalid } };
                }
                // Pass progress callback to the handler via args
                if (progressToken !== undefined) {
                    args._progress = (progress: number, total: number, message: string) =>
                        sendProgress(progressToken, progress, total, message);
                }
                const result_data = await handler(ctx, args);
                return {
                    jsonrpc: '2.0', id,
                    result: {
                        content: [{ type: 'text', text: JSON.stringify(result_data, null, 2) }],
                    },
                };
            }
            default: {
                if (req.method.startsWith('notifications/')) {
                    return { jsonrpc: '2.0', id: null };
                }
                return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${req.method}` } };
            }
        }
    } catch (err: any) {
        const code = err.code || -32603;
        return { jsonrpc: '2.0', id, error: { code, message: err.message || String(err) } };
    }
}

export function startServer(ctx: ServerContext): void {
    const rl = readline.createInterface({ input: process.stdin, terminal: false });

    rl.on('line', (line: string) => {
        const trimmed = line.trim();
        if (!trimmed) return;

        let parsed: unknown;
        try {
            parsed = JSON.parse(trimmed);
        } catch {
            error(null, -32700, 'Parse error');
            return;
        }

        if (
            parsed === null ||
            typeof parsed !== 'object' ||
            Array.isArray(parsed) ||
            typeof (parsed as JsonRpcRequest).method !== 'string'
        ) {
            const maybeId =
                parsed && typeof parsed === 'object' && !Array.isArray(parsed)
                    ? (parsed as JsonRpcRequest).id ?? null
                    : null;
            error(maybeId, -32600, 'Invalid Request');
            return;
        }

        const req = parsed as JsonRpcRequest;
        handleRequest(ctx, req).then((res) => {
            if (req.id !== undefined && req.id !== null) {
                send(res);
            }
        }).catch((err) => {
            if (req.id !== undefined && req.id !== null) {
                error(req.id, -32603, err.message || String(err));
            }
        });
    });

    rl.on('close', () => {
        process.exit(0);
    });
}
