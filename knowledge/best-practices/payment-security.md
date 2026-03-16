# Payment Security

## DO

- **Calculate amounts server-side**. Never trust client-submitted prices, quantities, or totals. Re-derive everything from your product catalog.
- **Use payment intents / server-side confirmation** (Stripe PaymentIntent, Braintree server-side). The server creates the intent, the client confirms it.
- **Validate amounts before capture**. Compare the PaymentIntent amount with your order total before confirming — detect tampering.
- **Use Stripe.js / payment provider SDKs** to tokenize card data. Card numbers never touch your server — this keeps you out of PCI DSS scope (SAQ A).
- **Verify webhook signatures** for payment events (payment_succeeded, refund, dispute). Don't trust client-side success redirects.
- **Implement idempotency keys** on payment creation to prevent double-charges on network retries.
- **Log payment events** (creation, success, failure, refund) with amount, currency, and order ID — never card details.
- **Use separate API keys** for test and production. Restrict production keys to specific IPs/servers.

## DON'T

- Accept `price` or `amount` from the frontend form or API request. This is the #1 payment vulnerability.
- Store card numbers, CVVs, or full expiry dates anywhere in your system — database, logs, error reports, analytics.
- Use test/sandbox API keys in production or production keys in development.
- Implement your own payment form that collects card numbers. Use provider-hosted fields (Stripe Elements, PayPal buttons).
- Process payments without verifying the user owns the payment method (3D Secure, address verification).
- Skip dispute/chargeback webhook handling — you need automated evidence collection.
- Put payment secrets (API keys, webhook secrets) in frontend bundles or client-accessible configs.

## Common AI Mistakes

- Sending `amount: req.body.amount` to Stripe instead of looking up the price server-side.
- Creating a `<input name="card_number">` field that posts to your server, bringing full PCI scope.
- Using the Stripe secret key in a Next.js page (client-side bundle) instead of an API route.
- Treating the Stripe checkout `success_url` redirect as payment confirmation instead of verifying via webhook.
- Forgetting to set `payment_intent_data.capture_method: 'manual'` when authorization and capture should be separate.
- Not implementing idempotency keys — network timeouts cause double charges.
