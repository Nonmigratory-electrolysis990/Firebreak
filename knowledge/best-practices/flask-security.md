# Flask Security

## DO

- **Set a strong `SECRET_KEY`** from environment variables. Use `secrets.token_hex(32)` to generate it. Flask uses it for session signing.
- **Disable debug mode in production** — `app.run(debug=True)` enables the Werkzeug debugger, which allows arbitrary code execution with the debugger PIN.
- **Enable CSRF protection** with Flask-WTF: `CSRFProtect(app)`. Include `{{ form.hidden_tag() }}` in every form.
- **Keep Jinja2 autoescape enabled** (it's on by default for `.html` templates). Verify with `app.jinja_env.autoescape`.
- **Configure session cookies securely**: `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`.
- **Use SQLAlchemy with parameterized queries**. For raw SQL: `db.session.execute(text("SELECT * FROM t WHERE id = :id"), {"id": user_id})`.
- **Validate file uploads**: check MIME type, limit file size, generate random filenames, and store outside the web root.

## DON'T

- Run `app.run(debug=True)` in production. The Werkzeug debugger console allows RCE if exposed.
- Use `flask.Markup()` or `|safe` filter on user-provided content — both disable escaping.
- Store `SECRET_KEY` in source code or use Flask's default (empty string). Sessions become forgeable.
- Use `pickle`-based session storage (e.g., `flask-session` with filesystem backend) without signing — deserialization attacks.
- Build SQL queries with f-strings or `%` formatting when using raw `db.session.execute()`.
- Serve user-uploaded files from the same domain without `Content-Disposition: attachment` — enables stored XSS.
- Trust `request.form` or `request.args` without validation. Use Marshmallow or Pydantic for structured validation.

## Common AI Mistakes

- Setting `app.secret_key = 'secret'` in example code that gets copied to production.
- Leaving `debug=True` in `app.run()` and deploying with `python app.py` instead of Gunicorn/uWSGI.
- Rendering user input with `Markup(f"<p>{user_input}</p>")` to "make it HTML."
- Writing `db.session.execute(f"SELECT * FROM users WHERE email = '{email}'")` — direct injection.
- Disabling CSRF globally because "it's a REST API" without implementing token-based auth instead.
