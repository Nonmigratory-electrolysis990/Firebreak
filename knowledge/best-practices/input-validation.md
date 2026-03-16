# Input Validation

## DO

- **Validate on the server**. Client-side validation is UX; server-side validation is security.
- **Use schema validation** (Zod, Joi, Pydantic, JSON Schema) at the API boundary. Define the expected shape and reject everything else.
- **Validate types strictly**: if you expect a string, reject objects and arrays. MongoDB `$gt` injection relies on receiving an object where a string is expected.
- **Validate length, range, and format**: email format, string max length, number min/max, date ranges.
- **Allowlist over denylist**: define what's valid rather than trying to block what's invalid.
- **Sanitize output, not just input**: encode HTML entities, escape SQL, use parameterized queries.

## DON'T

- Trust any data from the client — query params, body, headers, cookies are all attacker-controlled.
- Use regex for email validation beyond basic format check — use a library or just send a verification email.
- Silently coerce invalid input — reject it with a clear error.
- Validate only at the edge — validate again before database operations if the data passes through multiple layers.
- Write custom sanitization for SQL or HTML — use parameterized queries and template auto-escaping.

## Common AI Mistakes

- Accepting `req.body` directly without any validation or type checking.
- Using regex to "sanitize" SQL input instead of parameterized queries.
- Validating on the frontend with Zod but not on the API route.
- Checking `typeof x === 'string'` but not length, format, or content.
