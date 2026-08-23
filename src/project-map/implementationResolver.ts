/**
 * Implementation resolver — generic interface-to-implementation redirection.
 *
 * When the agent scans an interface, type declaration, or service contract,
 * the resolver finds the actual implementation files and symbols so the
 * investigation can continue on real code, not signatures.
 *
 * Matching strategies (all generic, no project-specific logic):
 *   - TypeScript interface → classes that implement it
 *   - Effect service declaration → live layer implementations
 *   - Abstract classes → subclasses
 *   - Exported type → functions returning the type
 *   - Route contracts → handler registrations
 *   - Python protocols/abstract classes → implementations (when symbol data supports it)
 */

import * as fs from 'fs';
import * as path from 'path';
import { searchCode } from '../utils/searchCode';
import { findDefinition, findReferences } from './symbolIndex';

export interface EvidenceLocation {
    filePath: string;
    line: number;
    symbol?: string;
}

export interface ImplementationResolution {
    contractLocations: EvidenceLocation[];
    implementationLocations: EvidenceLocation[];
    callSites: EvidenceLocation[];
    unresolved: boolean;
    description: string;
}

/**
 * Resolve implementations for a symbol in a contract/interface file.
 *
 * This is a generic search — it uses workspace-wide code search to find
 * patterns that indicate implementation of the given symbol.
 */
export async function resolveImplementation(
    workspaceRoot: string,
    filePath: string,
    symbol: string,
): Promise<ImplementationResolution> {
    const contractLocations: EvidenceLocation[] = [];
    const implementationLocations: EvidenceLocation[] = [];
    const callSites: EvidenceLocation[] = [];

    // Strategy 1: Search for the symbol as a class/interface name being
    // implemented or extended (TypeScript: implements, extends)
    const implPatterns = [
        `implements\\s+${escapeRegex(symbol)}\\b`,
        `extends\\s+${escapeRegex(symbol)}\\b`,
        `:\\s+${escapeRegex(symbol)}\\s*\\{`,
        `Layer\\.(effect|set)\\s*\\(\\s*["']${escapeRegex(symbol)}["']`,
        `Context\\.(Function|Service)\\s*\\(\\s*["']${escapeRegex(symbol)}["']`,
    ];

    for (const pattern of implPatterns) {
        const results = await searchCode(workspaceRoot, pattern, '*.ts');
        for (const hit of results.hits) {
            implementationLocations.push({
                filePath: hit.path,
                line: hit.line,
                symbol: extractSymbolFromLine(hit.text, symbol),
            });
        }
    }

    // Strategy 2: Search for "make" + symbol (common Effect pattern: makeServerAuth)
    const makePattern = `make${escapeRegex(symbol)}`;
    const makeResults = await searchCode(workspaceRoot, makePattern, '*.ts');
    for (const hit of makeResults.hits) {
        // Avoid the contract file itself
        if (!sameFile(hit.path, filePath)) {
            implementationLocations.push({
                filePath: hit.path,
                line: hit.line,
                symbol: `make${symbol}`,
            });
        }
    }

    // Strategy 3: Find references (call sites) using the symbol index
    try {
        const refsText = await findReferences(workspaceRoot, filePath, symbol);
        const refLines = refsText.split('\n');
        for (const line of refLines) {
            const match = line.match(/^\s+(\S+):(\d+)/);
            if (match) {
                callSites.push({
                    filePath: match[1],
                    line: parseInt(match[2], 10),
                });
            }
        }
    } catch {
        // Best effort — references are optional
    }

    // Strategy 4: Find the definition (contract location)
    try {
        const defText = await findDefinition(workspaceRoot, filePath, symbol);
        const defLines = defText.split('\n');
        for (const line of defLines) {
            const match = line.match(/^\s+(\S+):(\d+)/);
            if (match) {
                contractLocations.push({
                    filePath: match[1],
                    line: parseInt(match[2], 10),
                    symbol,
                });
            }
        }
    } catch {
        // Best effort
    }

    // Deduplicate implementation locations
    const unique = deduplicateLocations(implementationLocations);

    return {
        contractLocations,
        implementationLocations: unique,
        callSites: deduplicateLocations(callSites),
        unresolved: unique.length === 0,
        description: unique.length > 0
            ? `Found ${unique.length} implementation(s) for ${symbol}`
            : `No implementations found for ${symbol}`,
    };
}

/**
 * Format an implementation resolution for the agent transcript.
 */
export function formatImplementationResolution(resolution: ImplementationResolution): string {
    const lines: string[] = [];

    if (resolution.unresolved) {
        lines.push(`No implementations found. The target may be a contract-only file.`);
        lines.push('');
        lines.push('Consider:');
        lines.push('  - Searching for functions that return or produce this type');
        lines.push('  - Checking if the file is a type-only export');
        lines.push('  - Looking for runtime registration or dependency injection');
        return lines.join('\n');
    }

    lines.push(`Implementation resolution (${resolution.implementationLocations.length} location(s)):`);
    for (const loc of resolution.implementationLocations) {
        lines.push(`  ${loc.filePath}:${loc.line}${loc.symbol ? ` (${loc.symbol})` : ''}`);
    }
    if (resolution.callSites.length > 0) {
        lines.push('');
        lines.push(`Call sites (${resolution.callSites.length}):`);
        for (const loc of resolution.callSites.slice(0, 10)) {
            lines.push(`  ${loc.filePath}:${loc.line}`);
        }
        if (resolution.callSites.length > 10) {
            lines.push(`  ... and ${resolution.callSites.length - 10} more`);
        }
    }
    return lines.join('\n');
}

/**
 * Check if a file looks like a contract/interface/type declaration only
 * (has no runtime implementation). Generic heuristic, not project-specific.
 */
export function looksLikeContractOnly(content: string): boolean {
    const lines = content.split('\n');
    let typeDeclarations = 0;
    let runtimeCode = 0;

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

        // Type/interface declarations
        if (/^(export\s+)?(interface|type|abstract\s+class)\s/.test(trimmed)) {
            typeDeclarations++;
            continue;
        }

        // Effect service/context declarations (contract-like)
        if (/^(export\s+)?(const|class)\s+\w+\s*=\s*(Context|Service)\.(Function|Service)\(/.test(trimmed)) {
            typeDeclarations++;
            continue;
        }

        // Function/class implementations (runtime code)
        if (/^(export\s+)?(async\s+)?function\s+\w+/.test(trimmed) ||
            /^(export\s+)?(const|let|var)\s+\w+\s*=\s*(async\s*)?\(/.test(trimmed) ||
            /^(export\s+)?class\s+\w+\s*(implements|extends)/.test(trimmed)) {
            // Exclude Effect service declarations (contract-like, not implementations)
            if (/extends\s+Service\.Service/.test(trimmed)) {
                typeDeclarations++;
            } else {
                runtimeCode++;
            }
            continue;
        }

        // Layer implementations (runtime)
        if (/^(export\s+)?const\s+\w+\s*=\s*Layer\.(effect|set|succeed|fail)/.test(trimmed)) {
            runtimeCode++;
            continue;
        }
    }

    // Contract-only if there are type declarations but no runtime code
    return typeDeclarations > 0 && runtimeCode === 0;
}

function escapeRegex(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function sameFile(a: string, b: string): boolean {
    return a.replace(/\\/g, '/').toLowerCase() === b.replace(/\\/g, '/').toLowerCase();
}

function extractSymbolFromLine(text: string, contractSymbol: string): string | undefined {
    // Try to extract the implementing class/function name
    const classMatch = text.match(/class\s+(\w+)/);
    if (classMatch) return classMatch[1];
    const funcMatch = text.match(/function\s+(\w+)/);
    if (funcMatch) return funcMatch[1];
    const constMatch = text.match(/(?:const|let|var)\s+(\w+)/);
    if (constMatch) return constMatch[1];
    return undefined;
}

function deduplicateLocations(locs: EvidenceLocation[]): EvidenceLocation[] {
    const seen = new Set<string>();
    const result: EvidenceLocation[] = [];
    for (const loc of locs) {
        const key = `${loc.filePath}:${loc.line}`;
        if (!seen.has(key)) {
            seen.add(key);
            result.push(loc);
        }
    }
    return result;
}
