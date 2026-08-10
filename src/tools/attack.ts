import type { ServerContext } from '../mcp/types';

export async function toolAttack(_ctx: ServerContext, _args: any): Promise<unknown> {
    return {
        applied: false,
        note: 'Attack tool is in beta. Localhost endpoint red-team testing will be available in a future release. Use the VS Code extension for attack functionality in the meantime.',
    };
}
