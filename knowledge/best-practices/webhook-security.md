# Webhook Security

## DO

- **Verify HMAC signatures on every incoming webhook**. Compute `HMAC-SHA256(secret, raw_body)` and compare with the signature header using constant-time comparison.
- **Use the raw request body** for signature verification — not parsed/re-serialized JSON. Parsing then stringifying changes byte order.
- **Implement replay protection** with a timestamp header. Reject requests older than 5 minutes. Combine with a nonce/event-ID deduplication cache.
- **Set a short timeout** (5–10 seconds) for webhook processing. Return 200 immediately, process asynchronously. The sender will retry on timeout.
- **Store webhook secrets per provider**, rotatable without downtime. Support two active secrets during rotation (old + new).
- **Make handlers idempotent**. Webhooks are delivered at-least-once. Use the event ID to deduplicate and prevent double-processing.
- **Restrict webhook source IPs** where the provider publishes their IP ranges (Stripe, GitHub, etc.).
- **Log all webhook deliveries** — signature valid/invalid, event type, processing result.

```python
import hmac, hashlib
def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

## DON'T

- Parse the body before verifying the signature. Middleware that auto-parses JSON (Express `json()`) destroys the raw body needed for HMAC.
- Use `==` for signature comparison — timing attacks can recover the secret byte-by-byte. Use constant-time comparison.
- Process webhooks synchronously in the HTTP handler — timeouts cause retries cause duplicate processing.
- Trust webhook data without server-side validation. Verify critical fields (amounts, user IDs) against your own database.
- Expose your webhook secret in client-side code, logs, or error messages.
- Skip event-type filtering — process only the events you expect, reject unknown types.

## Common AI Mistakes

- Using `JSON.stringify(req.body)` for HMAC verification instead of the raw body buffer (Express destroys the raw body by default).
- Forgetting `express.raw({ type: 'application/json' })` on the webhook route, breaking signature verification.
- Comparing signatures with `===` instead of `crypto.timingSafeEqual()`.
- Not handling duplicate deliveries — charging a customer twice because the same `payment.succeeded` event arrived twice.
- Returning 500 on processing errors, causing infinite retries. Return 200 to acknowledge receipt, handle failures internally.
- Hardcoding the webhook secret instead of loading from environment/secrets manager.
