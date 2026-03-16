# Row Level Security (RLS) Policies

## DO

- **Enable RLS on every table** that contains user data: `ALTER TABLE t ENABLE ROW LEVEL SECURITY;`
- **Use ownership-based policies**: `USING (auth.uid() = user_id)` — each user sees only their rows.
- **Separate SELECT/INSERT/UPDATE/DELETE policies** — read access doesn't imply write access.
- **Test policies with multiple users** — create two test accounts and verify user A can't see user B's data.
- **Use `auth.uid()`** (Supabase) or `current_setting('app.user_id')` (raw Postgres) for the identity check.
- **Apply RLS to junction tables too** — a user_roles or team_members table without RLS leaks org structure.

## DON'T

- Use `USING (true)` on any table with user data. This disables RLS entirely.
- Forget `WITH CHECK` on INSERT/UPDATE policies — `USING` controls reads, `WITH CHECK` controls writes.
- Use `service_role` key client-side to bypass RLS — this defeats the entire purpose.
- Assume `FORCE ROW LEVEL SECURITY` is on by default — table owners bypass RLS unless forced.
- Create policies that reference other tables without indexing the join column — this kills performance.

## Common AI Mistakes

- Generating `USING (true)` as a "starting point" that never gets replaced.
- Enabling RLS but not creating any policies — this blocks ALL access, then the dev disables RLS to "fix" it.
- Writing SELECT policies but forgetting INSERT/UPDATE/DELETE policies.
- Not testing that the `anon` role is blocked — RLS must handle unauthenticated requests too.
