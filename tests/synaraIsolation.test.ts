/**
 * Synara isolation test — verifies that production code does not import
 * Synara-specific fixtures, seeds, or expected outcomes.
 *
 * This test PASSES now and must continue to pass after all future changes.
 * It is the primary guard against leaking Synara-specific knowledge into
 * production behavior.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

function getAllSourceFiles(dir: string, files: string[] = []): string[] {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') continue;
            getAllSourceFiles(fullPath, files);
        } else if (entry.name.endsWith('.ts') || entry.name.endsWith('.js')) {
            files.push(fullPath);
        }
    }
    return files;
}

describe('Synara isolation — production code must not import Synara fixtures', () => {
    it('no file under src/ imports from tests/fixtures/synara', () => {
        const srcDir = path.resolve(__dirname, '..', 'src');
        const sourceFiles = getAllSourceFiles(srcDir);

        const violations: string[] = [];
        for (const file of sourceFiles) {
            const content = fs.readFileSync(file, 'utf8');
            // Check for any import that references synara fixtures or seeds
            if (content.includes('tests/fixtures/synara') ||
                content.includes('fixtures/synara') ||
                content.includes('investigationSeeds') ||
                content.includes('synaraRegression') ||
                content.includes('SYNARA_INVESTIGATION_SEEDS') ||
                content.includes('EXPECTED_OUTCOMES')) {
                violations.push(file);
            }
        }

        expect(violations).toEqual([]);
    });

    it('no file under src/ contains hard-coded Synara file paths', () => {
        const srcDir = path.resolve(__dirname, '..', 'src');
        const sourceFiles = getAllSourceFiles(srcDir);

        const synaraPaths = [
            'apps/server/src/http.ts',
            'apps/server/src/wsRpc.ts',
            'apps/server/src/auth/Layers/ServerAuth.ts',
            'apps/server/src/auth/Services/ServerAuth.ts',
        ];

        const violations: string[] = [];
        for (const file of sourceFiles) {
            const content = fs.readFileSync(file, 'utf8');
            for (const synaraPath of synaraPaths) {
                if (content.includes(`"${synaraPath}"`) || content.includes(`'${synaraPath}'`)) {
                    violations.push(`${file}: contains "${synaraPath}"`);
                }
            }
        }

        expect(violations).toEqual([]);
    });
});
