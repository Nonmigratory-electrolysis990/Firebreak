# RabbitMQ Security

## DO

- **Delete or disable the default `guest` account** immediately. It has full admin access and can connect from localhost by default.
- **Enable TLS** on all listeners (AMQP 5671, management 15671). Use `ssl_options` in `rabbitmq.conf` with valid certificates.
- **Use vhost isolation** to separate environments (dev/staging/prod) and applications. Each service gets its own vhost with scoped permissions.
- **Apply least-privilege permissions** per user: configure/write/read regex patterns scoped to specific exchanges and queues.
- **Enable management plugin authentication** and restrict the management UI to internal networks or VPN.
- **Set per-queue and per-connection limits** (`x-max-length`, `x-max-length-bytes`, `consumer-timeout`) to prevent resource exhaustion.
- **Use Shovel or Federation** with TLS for cross-cluster communication instead of exposing AMQP ports.

## DON'T

- Leave the `guest:guest` account active in production — it's the first thing attackers try.
- Expose the management UI (port 15672) to the public internet.
- Grant `.*` (wildcard) permissions on configure/write/read to application users.
- Use unencrypted AMQP (port 5672) for cross-network traffic.
- Store credentials in message payloads without encryption — messages may be logged or dead-lettered.
- Disable `consumer-timeout` — stuck consumers can silently block queues.

## Common AI Mistakes

- Using `guest:guest` in connection strings in tutorials that get deployed to production.
- Configuring a single vhost `/` for all services with admin-level user permissions.
- Generating Docker setups that expose ports 5672 and 15672 on `0.0.0.0` without TLS or auth changes.
- Ignoring dead-letter queue setup, causing poison messages to block processing indefinitely.
- Not setting `x-max-length` on queues, allowing unbounded memory growth.
