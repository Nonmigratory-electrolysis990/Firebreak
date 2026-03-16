# SQL Injection Prevention

## DO

- **Use parameterized queries everywhere** — `?` placeholders (MySQL), `$1` (PostgreSQL), `@param` (SQL Server). Never interpolate.
```sql
-- Correct
SELECT * FROM users WHERE email = $1;
```
```python
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
```
```javascript
db.query("SELECT * FROM users WHERE id = $1", [userId]);
```
- **Use ORMs with parameterized bindings** — ActiveRecord, SQLAlchemy, Prisma, Sequelize all parameterize by default. Stick to their query builders.
- **Validate input types** before they reach the query layer — if `id` should be an integer, parse it as one. Reject non-numeric strings.
- **Apply least-privilege DB accounts** — the app user should not have `DROP`, `GRANT`, or `ALTER` permissions.
- **Use stored procedures** with parameterized inputs for complex operations — they constrain what SQL the app can execute.
- **Enable WAF rules** as a defense-in-depth layer, but never as the primary defense.

## DON'T

- Concatenate user input into SQL strings — `"SELECT * FROM users WHERE name = '" + name + "'"` is always exploitable.
- Use ORM raw query modes (`Sequelize.literal()`, `ActiveRecord.execute()`, SQLAlchemy `text()`) with user input without parameterizing.
- Trust client-side validation — SQL injection payloads bypass any frontend checks.
- Use blocklist filtering (stripping `'`, `--`, `UNION`) — there are infinite encoding bypasses (hex, Unicode, double-encoding).
- Allow dynamic table/column names from user input — parameterized queries cannot protect identifiers. Allowlist them explicitly.
- Log full SQL errors to users — stack traces reveal schema, table names, and DB version to attackers.

## Common AI Mistakes

- Generating `f"SELECT * FROM {table} WHERE id = {id}"` in Python — f-strings in SQL are always injection.
- Using template literals in Node.js: `` db.query(`SELECT * FROM users WHERE name = '${name}'`) `` — backticks don't parameterize.
- Parameterizing values but interpolating table/column names: `db.query("SELECT * FROM " + tableName + " WHERE id = $1", [id])`.
- Suggesting `mysql_real_escape_string()` or manual escaping instead of parameterized queries — escaping is fragile and charset-dependent.
- Writing Prisma `$queryRaw` with template literals without using `Prisma.sql` tagged template for parameterization.
- Creating a "safe query builder" that just wraps values in single quotes.
