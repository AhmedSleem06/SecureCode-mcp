export interface JsonRpcRequest {
    jsonrpc: '2.0';
    id?: number | string | null;
    method: string;
    params?: unknown;
}

export interface JsonRpcResponse {
    jsonrpc: '2.0';
    id: number | string | null;
    result?: unknown;
    error?: { code: number; message: string; data?: unknown };
}

export interface ToolDef {
    name: string;
    description: string;
    inputSchema: Record<string, unknown>;
}

export interface ServerContext {
    apiUrl: string;
    apiToken: string;
    workspaceRoot: string;
}
