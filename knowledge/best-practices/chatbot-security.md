# Chatbot and LLM Application Security

## DO

- **Treat all user input as untrusted** — apply the same input validation to chat prompts as you would to any form field. Sanitize before passing to the LLM.
- **Sanitize LLM output** before rendering. LLMs can generate HTML, JavaScript, SQL, and Markdown that executes if rendered unsafely.
- **Implement rate limiting** on chat endpoints — per-user and per-session. LLM API calls are expensive and slow; abuse can cause cost spikes and denial of service.
- **Filter PII from inputs and outputs** using regex patterns and NER models. Users may paste sensitive data; the model may hallucinate it.
- **Use system prompts to set boundaries** but don't rely on them as a security control. System prompts can be extracted or overridden via prompt injection.
- **Log conversations** (with PII redacted) for abuse detection and safety monitoring.
- **Set hard cost limits** on LLM API usage per user, per org, and globally. Alert at 50% threshold.

## DON'T

- Render LLM output as raw HTML. Always escape or use a safe Markdown renderer with HTML disabled.
- Give the LLM access to tools/functions that perform destructive operations without human confirmation.
- Rely on system prompts alone to prevent prompt injection — they're a guideline, not a security boundary.
- Pass user-controlled content directly into tool/function arguments without validation.
- Store full conversation histories with PII indefinitely. Apply retention policies and redaction.
- Trust LLM output for security decisions (authentication, authorization, access control).

## Common AI Mistakes

- Rendering chatbot responses with `dangerouslySetInnerHTML` or `v-html` without sanitization.
- Building chatbots that can execute database queries based on natural language input without sandboxing or parameterization.
- Not rate limiting chat endpoints because "the LLM is slow anyway" — a determined attacker can still run up a $10K API bill.
- Implementing "AI agents" that can call APIs, modify files, or execute code without confirmation steps.
- Logging full conversation histories including passwords, API keys, and PII that users paste into the chat.
