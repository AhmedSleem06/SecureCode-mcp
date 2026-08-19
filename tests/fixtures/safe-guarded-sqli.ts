// Fixture: guarded SQL injection — uses parameterized query.
// Expected verify verdict: UNPROVEN (the parameterization prevents injection)
// or no finding at all.
export const code = `
const db = require('./db');

export async function getUser(name) {
    const query = "SELECT * FROM users WHERE name = $1";
    return db.query(query, [name]);
}
`;

export const filePath = 'src/userServiceSafe.ts';
export const language = 'typescript';
export const vulnerabilityType = 'sql_injection';
export const line = 5;
export const evidence = `db.query(query, [name])`;
export const why = 'The query uses a parameterized statement ($1) with the user input passed as a bound parameter, preventing injection.';
