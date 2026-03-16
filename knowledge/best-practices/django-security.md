# Django Security

## DO

- **Keep `DEBUG = False`** in production. Debug mode exposes settings, source code, SQL queries, and full stack traces.
- **Set `ALLOWED_HOSTS`** explicitly. An empty list with `DEBUG = False` blocks all requests, but a wildcard `['*']` allows host header attacks.
- **Use the ORM for all queries**. If raw SQL is unavoidable, use parameterized queries: `Model.objects.raw('SELECT * FROM t WHERE id = %s', [user_id])`.
- **Keep `CsrfViewMiddleware` enabled**. Include `{% csrf_token %}` in every POST form. For AJAX, read the `csrftoken` cookie and send it as `X-CSRFToken`.
- **Rotate `SECRET_KEY`** on any suspected compromise. Generate it with `django.core.management.utils.get_random_secret_key()`. Never commit it to version control.
- **Use Django templates** — they auto-escape HTML by default. If you must render raw HTML, use `bleach` to sanitize first.
- **Set secure cookie flags**: `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `CSRF_COOKIE_HTTPONLY = True`, `SECURE_SSL_REDIRECT = True`.

## DON'T

- Decorate views with `@csrf_exempt` unless the endpoint is a webhook with its own signature verification.
- Use `|safe` template filter on user-supplied data — it disables auto-escaping and enables XSS.
- Set `SECRET_KEY` in `settings.py` directly. Load it from environment variables or a secrets manager.
- Use `extra()` or `RawSQL()` with string formatting. Both accept raw SQL and are injection vectors.
- Return `HttpResponse(traceback.format_exc())` in error handlers — use Django's built-in 500 handler.
- Keep `django.contrib.admindocs` or debug toolbar enabled in production.
- Use `ALLOWED_HOSTS = ['*']` — it defeats host header validation entirely.

## Common AI Mistakes

- Generating a project with `DEBUG = True` and never adding a production settings file.
- Hardcoding `SECRET_KEY = 'django-insecure-...'` (the default) and shipping it to production.
- Using `@csrf_exempt` on API views instead of using Django REST Framework's token authentication.
- Writing `cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")` — direct SQL injection.
- Disabling `CsrfViewMiddleware` globally because "the frontend is a SPA."
