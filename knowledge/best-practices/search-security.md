# Search Security

## DO

- **Parameterize all search queries**. Use parameterized queries or your ORM's query builder — never interpolate user input into SQL, Elasticsearch DSL, or MongoDB queries.
- **Filter search results by the authenticated user's permissions**. Apply tenant/ownership filters at the query level, not after fetching results.
- **Limit pagination** — cap `page_size` (max 100) and `offset` (max 10,000). Use cursor-based pagination for deep result sets.
- **Sanitize search input** for the specific query engine. Escape special characters in Elasticsearch (`+`, `-`, `&&`, `||`, `!`, `(`, `)`, `{`, `}`, `[`, `]`, `^`, `"`, `~`, `*`, `?`, `:`, `\`, `/`).
- **Redact sensitive fields** from search results. Don't return full SSNs, passwords, API keys, or internal IDs in search responses.
- **Rate limit search endpoints** aggressively. Search is expensive — 10–20 requests per minute per user for full-text search.
- **Log search queries** for abuse detection (data scraping patterns, injection attempts).
- **Use separate search indexes** per tenant in multi-tenant systems. Shared indexes with runtime filtering risk cross-tenant leakage.

## DON'T

- Concatenate user input into raw Elasticsearch/Solr/MongoDB queries. This is query injection, equivalent to SQL injection.
- Return all matching fields — only return what the UI needs. Internal fields (`_score`, `_id`, internal timestamps) should be stripped.
- Allow unbounded result sets (`size: 999999`). This enables data exfiltration in a single request.
- Expose raw search engine errors to the client. They reveal index structure, field names, and query syntax.
- Trust client-side filtering to enforce access control. "Hide" in the UI is not access control.
- Allow search on fields that contain secrets (hashed passwords, tokens, internal notes).

## Common AI Mistakes

- Building Elasticsearch queries with string interpolation: `{ "query": { "match": { "name": "${userInput}" } } }`.
- Forgetting to add tenant_id filter to search queries in multi-tenant apps — returning other tenants' data.
- Setting no max on `page_size`, allowing `?page_size=100000` to dump the entire index.
- Returning full user objects (including email, phone, hashed password) in search results instead of projected fields.
- Not escaping Lucene special characters in Elasticsearch, allowing query syntax manipulation.
- Implementing autocomplete/typeahead without rate limiting — enables rapid enumeration of all records.
