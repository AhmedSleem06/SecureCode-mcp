// Fixture: vulnerability that requires a running database to verify.
// Expected verify verdict: INCONCLUSIVE (cannot test without a live DB server).
export const code = `
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function rawQuery(sql: string) {
    // Vulnerable: raw SQL string passed directly to the DB.
    const client = await pool.connect();
    try {
        return await client.query(sql);
    } finally {
        client.release();
    }
}
`;

export const filePath = 'src/rawQuery.ts';
export const language = 'typescript';
export const vulnerabilityType = 'sql_injection';
export const line = 9;
export const evidence = `await client.query(sql)`;
export const why = 'Raw SQL string is passed directly to the database without parameterization. However, verification requires a running PostgreSQL instance (process.env.DATABASE_URL), which is not available in the sandbox.';
