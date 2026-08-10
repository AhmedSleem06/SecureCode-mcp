import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { AuditEntry } from './types';

const AUDIT_DIR = path.join(os.homedir(), '.securecode');
const AUDIT_FILE = path.join(AUDIT_DIR, 'approval-audit.log');

export function appendAudit(entry: AuditEntry): void {
    try {
        if (!fs.existsSync(AUDIT_DIR)) {
            fs.mkdirSync(AUDIT_DIR, { recursive: true, mode: 0o700 });
        }
        const line = JSON.stringify(entry) + '\n';
        fs.appendFileSync(AUDIT_FILE, line, { mode: 0o600 });
    } catch {
        // best effort — audit failure must not block the operation
    }
}

export function readAudit(limit: number = 100): AuditEntry[] {
    try {
        if (!fs.existsSync(AUDIT_FILE)) return [];
        const raw = fs.readFileSync(AUDIT_FILE, 'utf8');
        const lines = raw.trim().split('\n').filter(Boolean);
        return lines.slice(-limit).map((line) => JSON.parse(line) as AuditEntry);
    } catch {
        return [];
    }
}
