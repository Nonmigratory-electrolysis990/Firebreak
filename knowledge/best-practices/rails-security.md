# Rails Security

## DO

- **Use strong parameters** on every controller action. Call `params.require(:model).permit(:field1, :field2)` — never pass `params` directly to `create` or `update`.
- **Keep CSRF protection enabled** — `protect_from_forgery with: :exception` is the default. For API-only controllers, use token-based auth instead of disabling CSRF.
- **Force SSL in production** with `config.force_ssl = true` in `config/environments/production.rb`. This sets HSTS and redirects HTTP.
- **Use `has_secure_password`** with bcrypt for password storage. Rails handles salting and hashing automatically.
- **Set Content Security Policy** in `config/initializers/content_security_policy.rb`. Rails 7+ provides a DSL for CSP headers.
- **Scope all queries to the current user**: `current_user.posts.find(params[:id])` instead of `Post.find(params[:id])` — prevents IDOR.
- **Use `sanitize()` or `sanitize_sql_array()`** if you must interpolate into HTML or SQL. Rails views auto-escape by default.

## DON'T

- Use `params.permit!` — it permits all parameters and re-enables mass assignment vulnerabilities.
- Call `skip_before_action :verify_authenticity_token` on non-API controllers. Use `protect_from_forgery with: :null_session` for APIs.
- Write raw SQL with string interpolation: `where("name = '#{params[:name]}'")`. Use `where("name = ?", params[:name])`.
- Use `html_safe` or `raw()` on user input in views. Both disable auto-escaping.
- Store secrets in `config/secrets.yml` committed to git. Use Rails credentials (`rails credentials:edit`) or environment variables.
- Disable `config.force_ssl` because "the load balancer handles it" — you lose HSTS and secure cookie flags.
- Use `find_by_sql` with interpolated strings. Always parameterize.

## Common AI Mistakes

- Generating a scaffold and using `params.permit!` to "make it work quickly."
- Disabling CSRF with `skip_before_action :verify_authenticity_token` at the `ApplicationController` level.
- Writing `Post.find(params[:id])` without scoping to the current user — any user can access any post by changing the ID.
- Using `raw(user.bio)` in views to "preserve formatting" — direct XSS.
- Committing `master.key` or `config/credentials.yml.enc` decryption key to the repository.
