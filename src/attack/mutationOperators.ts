/**
 * Mutation operators — apply security fixes to vulnerable code to create
 * a "secure mutation." The mutation test then checks whether the test
 * script can distinguish between the original (vulnerable) code and the
 * mutated (secure) code.
 *
 * A discriminating test PASSES on the vulnerable code and FAILS on the
 * secure mutation. This proves the test is actually testing the security
 * property, not just exercising the code path.
 */

export type VulnerabilityType =
    | 'broken_access_control'
    | 'missing_auth'
    | 'missing_ownership'
    | 'sql_injection'
    | 'path_traversal'
    | 'command_injection'
    | 'xss'
    | 'ssrf'
    | 'ssti'
    | 'missing_input_validation'
    | 'secrets_in_source'
    | 'generic';

export interface MutationResult {
    mutated: boolean;
    mutatedCode: string;
    description: string;
}

/**
 * Apply a mutation operator for the given vulnerability type to the
 * vulnerable code. Returns the mutated (secure) code or `mutated: false`
 * if no operator is available.
 */
export function applyMutation(
    code: string,
    vulnerabilityType: string,
    line: number,
): MutationResult {
    const lines = code.split('\n');
    const lineIdx = Math.max(0, Math.min(line - 1, lines.length - 1));
    const targetLine = lines[lineIdx];

    switch (vulnerabilityType as VulnerabilityType) {
        case 'broken_access_control':
        case 'missing_auth': {
            // Insert a 401/403 rejection before the target line
            const indent = (targetLine.match(/^\s*/) || [''])[0];
            const guard = `${indent}if (!isAuthenticated || !hasPermission) { return res ? res.status(403).json({ error: 'forbidden' }) : null; }`;
            const mutated = [...lines];
            mutated.splice(lineIdx, 0, guard);
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Added authentication/authorization guard before the vulnerable line',
            };
        }

        case 'missing_ownership': {
            // Insert an ownership check before the target line
            const indent = (targetLine.match(/^\s*/) || [''])[0];
            const guard = `${indent}if (resource.ownerId !== requesterId) { throw new Error('not owner'); }`;
            const mutated = [...lines];
            mutated.splice(lineIdx, 0, guard);
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Added ownership check before the vulnerable line',
            };
        }

        case 'sql_injection': {
            // Replace string interpolation in SQL queries with parameter placeholders
            const mutatedLine = targetLine
                .replace(/`([^`]*\$\{[^}]+\}[^`]*)`/g, '?')
                .replace(/'([^']*\+[^']*)'/g, '?')
                .replace(/"\s*\+\s*\w+\s*\+"/g, '?');
            if (mutatedLine === targetLine) {
                return { mutated: false, mutatedCode: code, description: 'No SQL interpolation found to mutate' };
            }
            const mutated = [...lines];
            mutated[lineIdx] = mutatedLine;
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Replaced SQL string interpolation with parameter placeholders',
            };
        }

        case 'path_traversal': {
            // Add path containment validation
            const indent = (targetLine.match(/^\s*/) || [''])[0];
            const guard = `${indent}const safePath = path.resolve(baseDir, userInput).replace(/\\.\\.\\//g, ''); if (!safePath.startsWith(baseDir)) { throw new Error('path traversal blocked'); }`;
            const mutated = [...lines];
            mutated.splice(lineIdx, 0, guard);
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Added path containment validation before file access',
            };
        }

        case 'command_injection': {
            // Replace shell string execution with argument-array execution
            const mutatedLine = targetLine
                .replace(/exec\(\s*`([^`]*)`\s*\)/g, 'execFile($1.split(" "))')
                .replace(/exec\(\s*([^`]+)\s*\+\s*([^)]+)\)/g, 'execFile([$1, $2])');
            if (mutatedLine === targetLine) {
                return { mutated: false, mutatedCode: code, description: 'No command injection pattern found to mutate' };
            }
            const mutated = [...lines];
            mutated[lineIdx] = mutatedLine;
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Replaced shell string execution with argument-array execution',
            };
        }

        case 'xss': {
            // Add HTML escaping before output
            const indent = (targetLine.match(/^\s*/) || [''])[0];
            const guard = `${indent}const safeOutput = userInput.replace(/<script>/gi, '&lt;script&gt;').replace(/on\\w+=/gi, '');`;
            const mutated = [...lines];
            mutated.splice(lineIdx, 0, guard);
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Added HTML escaping before output',
            };
        }

        case 'ssrf': {
            // Add URL allowlist validation
            const indent = (targetLine.match(/^\s*/) || [''])[0];
            const guard = `${indent}const allowedHosts = ['localhost', '127.0.0.1']; const url = new URL(targetUrl); if (!allowedHosts.includes(url.hostname)) { throw new Error('SSRF blocked'); }`;
            const mutated = [...lines];
            mutated.splice(lineIdx, 0, guard);
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Added URL allowlist validation before external request',
            };
        }

        case 'ssti': {
            // Replace template rendering with safe string output
            const mutatedLine = targetLine
                .replace(/render\(/g, 'renderText(')
                .replace(/ejs\.render\(/g, 'String(');
            if (mutatedLine === targetLine) {
                return { mutated: false, mutatedCode: code, description: 'No SSTI pattern found to mutate' };
            }
            const mutated = [...lines];
            mutated[lineIdx] = mutatedLine;
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Replaced template rendering with safe string output',
            };
        }

        case 'missing_input_validation': {
            // Add input validation guard
            const indent = (targetLine.match(/^\s*/) || [''])[0];
            const guard = `${indent}if (!input || typeof input !== 'string' || input.length > 1000) { throw new Error('invalid input'); }`;
            const mutated = [...lines];
            mutated.splice(lineIdx, 0, guard);
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Added input validation guard',
            };
        }

        case 'secrets_in_source': {
            // Replace hardcoded secret with environment variable reference
            const mutatedLine = targetLine
                .replace(/['"][^'"]*(?:sk-|ghp_|AKIA|password|secret|token|apiKey|api_key)[^'"]*['"]/gi, 'process.env.SECRET_KEY')
                .replace(/=\s*['"][a-f0-9]{32,}['"]/gi, '= process.env.SECRET_KEY');
            if (mutatedLine === targetLine) {
                return { mutated: false, mutatedCode: code, description: 'No hardcoded secret found to mutate' };
            }
            const mutated = [...lines];
            mutated[lineIdx] = mutatedLine;
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Replaced hardcoded secret with environment variable reference',
            };
        }

        default:
            return {
                mutated: false,
                mutatedCode: code,
                description: `No mutation operator available for vulnerability type: ${vulnerabilityType}`,
            };
    }
}
