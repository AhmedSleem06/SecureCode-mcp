import type { ServerContext } from '../mcp/types';
import {
    recordFalsePositive,
    loadAgentMemory,
    clearAgentMemory,
    removeFalsePositive,
    addKnownFact,
    formatMemoryForPrompt,
} from '../project-map/agentMemory';

export async function toolMemory(ctx: ServerContext, args: any): Promise<unknown> {
    const action = args.action as string;

    switch (action) {
        case 'list': {
            const memory = loadAgentMemory(ctx.workspaceRoot);
            return {
                falsePositives: {
                    count: memory.falsePositives.length,
                    entries: memory.falsePositives.map(fp => ({
                        id: fp.id,
                        findingType: fp.findingType,
                        file: fp.file,
                        line: fp.line,
                        pattern: fp.pattern,
                        reason: fp.reason,
                        addedAt: fp.addedAt,
                    })),
                },
                knownFacts: {
                    count: memory.knownFacts.length,
                    entries: memory.knownFacts.map(kf => ({
                        id: kf.id,
                        fact: kf.fact,
                        source: kf.source,
                        addedAt: kf.addedAt,
                    })),
                },
                formatted: formatMemoryForPrompt(memory),
            };
        }

        case 'add-fact': {
            if (!args.fact || !args.source) {
                throw new Error('Missing required parameters "fact" and "source" for action "add-fact".');
            }
            const entry = addKnownFact(ctx.workspaceRoot, args.fact, args.source);
            if (!entry) {
                return { success: false, message: 'Fact already exists (duplicate).' };
            }
            return {
                success: true,
                recorded: { id: entry.id, fact: entry.fact, source: entry.source, addedAt: entry.addedAt },
                message: 'Known fact added. The agent will use this in future scans.',
            };
        }

        case 'record-false-positive': {
            const required = ['filePath', 'findingType', 'line', 'evidence', 'reason'];
            for (const field of required) {
                if (!args[field]) {
                    throw new Error(`Missing required parameter '${field}' for action "record-false-positive".`);
                }
            }
            const entry = recordFalsePositive(ctx.workspaceRoot, {
                filePath: args.filePath,
                findingType: args.findingType,
                line: args.line,
                evidence: args.evidence,
                reason: args.reason,
                pattern: args.pattern,
                codeSnippet: args.codeSnippet,
            });
            if (!entry) {
                return { success: false, error: 'Invalid input — could not record false positive.' };
            }
            return {
                success: true,
                recorded: {
                    id: entry.id,
                    findingType: entry.findingType,
                    pattern: entry.pattern,
                    reason: entry.reason,
                    addedAt: entry.addedAt,
                },
                message: 'False positive recorded. The agent will not report similar patterns in future scans of this workspace.',
            };
        }

        case 'clear': {
            if (args.id) {
                const removed = removeFalsePositive(ctx.workspaceRoot, args.id);
                return { success: removed, message: removed ? `Removed false positive ${args.id}.` : `False positive ${args.id} not found.` };
            }
            const cleared = clearAgentMemory(ctx.workspaceRoot);
            return {
                success: cleared,
                message: cleared
                    ? 'All agent memory cleared (false positives + known facts).'
                    : 'No agent memory file found — nothing to clear.',
            };
        }

        default:
            throw new Error(`Unknown action "${action}". Valid actions: list, add-fact, record-false-positive, clear.`);
    }
}
