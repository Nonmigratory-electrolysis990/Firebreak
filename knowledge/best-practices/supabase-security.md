# Supabase Security

## DO

- **Enable RLS on every table** — the moment you create a table, add `ALTER TABLE t ENABLE ROW LEVEL SECURITY;`. A table without RLS is fully readable/writable via the anon key.
- **Use `auth.uid()`** in every RLS policy to scope rows to the authenticated user: `USING (user_id = auth.uid())`.
- **Isolate the service role key** to server-only environments (edge functions, backend API). Never expose it in client bundles.
- **Create separate policies for SELECT, INSERT, UPDATE, DELETE** — a single permissive policy for all operations is almost always too broad.
- **Set storage bucket policies** per-file or per-path. Default buckets are public. Use `storage.objects` RLS policies with `auth.uid()`.
- **Validate inputs in Edge Functions** before passing them to database queries. Edge Functions bypass RLS when using the service client.
- **Use `supabase.auth.getUser()`** (server-side, hits auth server) instead of `supabase.auth.getSession()` for security-critical checks — sessions can be tampered client-side.

## DON'T

- Use the `service_role` key in client-side code. It bypasses all RLS — full database access for anyone who reads your bundle.
- Write RLS policies with `USING (true)` on production tables. This makes the table publicly readable.
- Trust `auth.jwt()` claims for authorization in RLS without verifying custom claims are set by a trusted source.
- Store files in public buckets assuming "nobody will guess the URL." Bucket URLs are predictable.
- Skip the `WITH CHECK` clause on INSERT/UPDATE policies — `USING` only controls reads, `WITH CHECK` controls writes.
- Call `supabase.rpc()` with the service client from the browser — any RPC executed with service role ignores RLS.
- Rely on Supabase email confirmation alone as account verification without rate-limiting signups.

## Common AI Mistakes

- Creating tables and never enabling RLS because "the app uses auth."
- Using `createClient(url, serviceRoleKey)` in a Next.js client component.
- Writing an RLS policy like `CREATE POLICY "allow all" ON todos FOR ALL USING (true) WITH CHECK (true);` as a placeholder and never replacing it.
- Fetching `supabase.auth.getSession()` in middleware and trusting it for authorization without `getUser()` verification.
- Building file upload without storage policies, leaving every uploaded file publicly accessible by default.
