export type EntryPointKind = 'http' | 'rpc' | 'export' | 'event' | 'cli';

export interface InventoryEntryPoint {
    id: string;
    kind: EntryPointKind;
    name: string;
    line: number;
    method?: string;
    path?: string;
    endLine?: number;
    framework?: string;
    middleware?: string[];
}

export interface InventoryInput {
    id: string;
    entryId: string | null;
    source: string;
    line: number;
    sourceType?: string;
}

export interface InventorySink {
    id: string;
    kind: string;
    line: number;
    callExpression: string;
    attackType?: string;
    severity?: string;
    entryId?: string | null;
    enclosingFunction?: string | null;
    detector?: 'sinkFinder' | 'taint' | 'pattern';
}

export interface InventoryGuard {
    id: string;
    name: string;
    line: number;
    protects?: string[];
    kind?: 'named' | 'middleware' | 'inline';
    lines?: number[];
    guardType?: string;
    effectiveAgainst?: string[];
}

export type ConnectedRelation = 'imports' | 'imported_by' | 'middleware' | 'config' | 'callee';

export interface InventoryConnectedFile {
    file: string;
    relation: ConnectedRelation;
    reason: string;
}

export interface InventoryFlow {
    from: string;
    to: string;
    via: string[];
    crossFile: boolean;
    attackType?: string;
}

export interface FileInventory {
    file: string;
    entryPoints: InventoryEntryPoint[];
    inputs: InventoryInput[];
    sinks: InventorySink[];
    guards: InventoryGuard[];
    roles: string[];
    connected: InventoryConnectedFile[];
    flows: InventoryFlow[];
    stats?: {
        lines: number;
        elapsedMs: number;
        truncated: string[];
        failedSteps: string[];
        stepMs?: Record<string, number>;
    };
}
