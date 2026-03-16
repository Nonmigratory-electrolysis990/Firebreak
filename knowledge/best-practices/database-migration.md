# Database Migration Security

## DO

- **Make every migration reversible** with explicit `up` and `down` methods. Test rollbacks in staging before applying to production.
- **Use non-destructive migrations** in production: add columns, create new tables, add indexes. Never drop columns or tables in the same deploy as the code change.
- **Encrypt sensitive columns during migration** using application-level encryption (envelope encryption with KMS). Don't store PII in new plaintext columns.
- **Run migrations in transactions** where supported (PostgreSQL). If any statement fails, the entire migration rolls back cleanly.
- **Apply migrations with a dedicated database user** that has schema-change privileges but is separate from the application user.
- **Review migration SQL** before production execution. Use `--dry-run` or `--sql` flags to preview generated SQL.
- **Use the expand-contract pattern** for breaking changes: (1) add new column, (2) dual-write, (3) backfill, (4) switch reads, (5) remove old column in a future release.

## DON'T

- Run `DROP TABLE` or `DROP COLUMN` in the same release as the code that removes usage. The old code version may still be running during rolling deploys.
- Use destructive operations (`TRUNCATE`, `DROP`, `DELETE FROM`) in automated migration scripts without explicit safeguards.
- Perform data transformations in migrations that lock large tables for extended periods. Use batched updates with `LIMIT` and sleep intervals.
- Store migration credentials in source code. Use environment variables or a secrets manager.
- Skip testing migrations against a production-sized dataset. A migration that takes 1 second on dev may lock a table for 30 minutes in production.
- Apply migrations directly in production without a staging environment test.

## Common AI Mistakes

- Generating migrations with `DROP COLUMN` for renamed fields instead of the add-migrate-drop pattern.
- Creating migrations that add `NOT NULL` columns without a default value, failing on existing rows.
- Not wrapping migrations in transactions, leaving the database in a half-migrated state on failure.
- Generating `ALTER TABLE` on large tables without considering lock duration and application downtime.
- Using ORM auto-migration (`db.AutoMigrate`, `sequelize.sync({alter: true})`) in production.
