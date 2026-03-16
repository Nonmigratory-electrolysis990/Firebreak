# Serverless Security

## DO

- **Apply function-level IAM policies**. Each Lambda/Cloud Function gets its own role with only the permissions it needs — never a shared role across all functions.
- **Validate all event inputs**. Events from API Gateway, S3, SQS, EventBridge, and other triggers are user-influenced. Validate and sanitize every field.
- **Set execution timeouts** appropriate to the function's workload. A function without a timeout can run (and bill) until the platform maximum if an attacker triggers infinite loops.
- **Load secrets from a secrets manager** (AWS Secrets Manager, SSM Parameter Store, GCP Secret Manager) at cold start, cache in memory. Never hardcode in function code or environment variables.
- **Use reserved concurrency** to limit blast radius. A function under attack shouldn't consume all available concurrency in the account.
- **Enable function-level logging** and send to a centralized log platform. Include request IDs for tracing.
- **Keep function packages minimal**. Fewer dependencies mean fewer vulnerabilities and smaller attack surface.

## DON'T

- Attach a broad IAM role (`AdministratorAccess`, `AmazonS3FullAccess`) to a function. Each function should have exactly the permissions it uses.
- Store secrets in function environment variables in plaintext. They're visible in the console and API. Use encrypted references or secrets manager.
- Trust event data without validation. S3 event keys, SQS message bodies, and API Gateway parameters are all attacker-controlled.
- Set execution timeout to the maximum (15 min for Lambda) by default. Use the minimum viable timeout.
- Share `/tmp` directory data between invocations for sensitive state — the execution environment may be reused by concurrent invocations.
- Skip dependency scanning because "it's just a small function." Small functions with vulnerable dependencies are still exploitable.
- Use wildcard resource ARNs (`Resource: "*"`) in IAM policies. Scope to specific resources.

## Common AI Mistakes

- Creating a single IAM role shared by all Lambda functions with `"Action": "s3:*", "Resource": "*"`.
- Putting `DATABASE_URL=postgres://user:password@host/db` directly in function environment variables.
- Building an API Gateway handler that passes `event.body` directly to a database query without validation.
- Setting `Timeout: 900` (15 minutes) on every function "just in case."
- Writing a function that uses `/tmp` to cache auth tokens between invocations without considering execution environment reuse by different users.
