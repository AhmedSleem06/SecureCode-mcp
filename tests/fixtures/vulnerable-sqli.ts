// Fixture: vulnerable SQL injection via string concatenation.
// Expected verify verdict: PROVEN (the exploit reaches the DB and executes).
export const code = `
const db = require('./db');

export async function getUser(name) {
    const query = "SELECT * FROM users WHERE name = '" + name + "'";
    return db.query(query);
}
`;

export const filePath = 'src/userService.ts';
export const language = 'typescript';
export const vulnerabilityType = 'sql_injection';
export const line = 5;
export const evidence = `query = "SELECT * FROM users WHERE name = '" + name + "'"`;
export const why = 'User-controlled `name` is concatenated directly into the SQL query without parameterization, allowing injection.';
