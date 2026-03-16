# REST API Design Security

## DO

- **Authenticate every endpoint** — use middleware/guards that run before route handlers. No endpoint should be accidentally public.
- **Return consistent error responses** with a standard schema: `{ "error": { "code": "RATE_LIMIT", "message": "..." } }`. Never expose stack traces or internal paths.
- **Implement rate limiting per-user and per-IP** at the gateway level. Return `429 Too Many Requests` with `Retry-After` header.
- **Use cursor-based pagination** instead of offset-based for large datasets. Offset pagination leaks total count and allows enumeration.
- **Version your API** (`/v1/`, header, or query param) so security fixes can ship without breaking clients.
- **Validate Content-Type** on every request. Reject requests with unexpected content types to prevent type confusion attacks.
- **Use HTTP methods correctly** — GET for reads (no side effects), POST/PUT/PATCH for writes, DELETE for removal. Enforce this with method allowlists.

## DON'T

- Return different error structures for auth failures vs validation errors — inconsistency helps attackers fingerprint your API.
- Expose auto-increment IDs — use UUIDs or hashids. Sequential IDs reveal entity counts and enable enumeration.
- Allow unbounded page sizes (`?limit=999999`). Set a max and enforce it server-side.
- Return `200 OK` with an error body. Use proper HTTP status codes (400, 401, 403, 404, 422, 429, 500).
- Put sensitive data in query strings — they appear in logs, browser history, and referrer headers.
- Implement HATEOAS links that bypass authorization — each linked resource must still be auth-checked.
- Allow `GET` requests to perform mutations (delete, update).

## Common AI Mistakes

- Generating CRUD APIs with no authentication middleware — every route is publicly accessible.
- Using `200` for all responses with `{ "success": false }` in the body.
- Implementing pagination with `?page=1&limit=100` and no upper bound on `limit`.
- Returning full user objects (including password hashes, emails) in list endpoints.
- Hardcoding API version in URLs but not actually maintaining backward compatibility.
