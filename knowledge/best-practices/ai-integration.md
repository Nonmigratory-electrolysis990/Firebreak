# AI/ML API Integration Security

## DO

- **Store API keys in a secrets manager** (Vault, AWS Secrets Manager, environment variables). Never commit API keys to source code or config files.
- **Validate and sanitize LLM outputs** before using them in application logic. Treat AI-generated content as untrusted input — it can contain injection payloads.
- **Implement output guardrails** — validate that generated code, SQL, or commands match expected patterns before execution.
- **Set spending limits and alerts** at the API provider level and in your application. A bug in a retry loop can burn through thousands of dollars in minutes.
- **Handle hallucinations gracefully** — never use AI output as ground truth for security decisions, financial calculations, or medical/legal advice without verification.
- **Use the minimum-capability model** for each task. Don't send all requests to GPT-4 when GPT-3.5 handles classification fine — it reduces cost and attack surface.
- **Implement circuit breakers** for AI API calls. If the API is slow or erroring, fail gracefully instead of queuing unbounded requests.

## DON'T

- Hardcode API keys in source code: `openai.api_key = "sk-..."`. Use environment variables or a secrets manager.
- Execute AI-generated code or SQL without sandboxing and validation. The model can generate `DROP TABLE` or `rm -rf /`.
- Retry failed AI API calls indefinitely without backoff and limits. Exponential backoff with a max retry count prevents cost spirals.
- Pass sensitive data (PII, credentials, proprietary code) to external AI APIs without reviewing the provider's data retention policy.
- Trust AI-generated content for access control decisions ("The AI said this user is an admin").
- Cache AI responses without considering that the same prompt can generate different (potentially harmful) outputs.

## Common AI Mistakes

- Committing `.env` files with `OPENAI_API_KEY=sk-...` to public repositories.
- Building features that execute AI-generated code server-side: `eval(aiResponse.code)`.
- Not implementing cost controls — a loop that retries on every error can spend $1000/hour on GPT-4.
- Sending full database records (including PII) as context to external AI APIs.
- Using AI to generate SQL queries and executing them directly without parameterization or validation.
