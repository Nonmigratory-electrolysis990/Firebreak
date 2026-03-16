# Redis Security

## DO

- **Require AUTH with a strong password** (64+ char random string). Use ACLs (Redis 6+) to create per-service users with minimal command sets.
- **Enable TLS** for all client-to-server and replication connections. Use `tls-port` instead of the default `port` directive.
- **Bind to specific interfaces** (`bind 127.0.0.1` or internal IPs). Never bind to `0.0.0.0` in production.
- **Set `maxmemory` and `maxmemory-policy`** to prevent OOM. Use `allkeys-lru` or `volatile-ttl` depending on your use case.
- **Rename or disable dangerous commands** (`FLUSHALL`, `FLUSHDB`, `DEBUG`, `CONFIG`, `KEYS`) via `rename-command` in redis.conf.
- **Use separate Redis instances** (or databases) for different trust levels — don't share a cache instance with a session store.
- **Run Redis in a private network** behind a firewall. Use SSH tunnels or VPN for remote access.

## DON'T

- Expose Redis on port 6379 to the public internet — it will be compromised within minutes.
- Use `requirepass` alone without ACLs on Redis 6+ — it's a single shared password with full access.
- Use the `default` user with full permissions in production.
- Store secrets or PII in Redis without encryption at the application layer — Redis stores everything in plaintext.
- Use `KEYS *` in production — it blocks the single-threaded event loop. Use `SCAN` instead.
- Disable `protected-mode` to "fix" connection issues — fix your bind/auth config instead.
- Run Redis as root.

## Common AI Mistakes

- Generating `docker-compose.yml` with Redis exposed on `0.0.0.0:6379` and no password.
- Using `KEYS pattern` in application code instead of `SCAN`.
- Setting `requirepass: "redis"` or `requirepass: "password"` in example configs that get copied to production.
- Connecting to Redis without TLS because "it's on the same network."
- Ignoring `maxmemory` config, letting Redis consume all available RAM and crash the host.
