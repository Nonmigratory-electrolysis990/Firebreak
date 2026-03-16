# File Inclusion Prevention (LFI/RFI)

## DO

- **Allowlist permitted file paths** — maintain an explicit map of allowed includes. Never derive file paths from user input.
```php
// PHP: Allowlisted includes
$allowed = ['header' => 'includes/header.php', 'footer' => 'includes/footer.php'];
$page = $allowed[$_GET['page']] ?? null;
if ($page) include $page;
```
- **Disable remote file includes** — set `allow_url_include = Off` and `allow_url_fopen = Off` in PHP. Most languages don't support remote includes natively.
- **Canonicalize and validate paths** before any file operation — resolve symlinks and `..` sequences, then verify the result is within the allowed directory.
- **Use static routing** instead of dynamic file-based routing — map routes to handlers explicitly rather than including files based on URL parameters.
- **Restrict file permissions** — the web server user should not have read access to files outside the application directory (`/etc/passwd`, `/proc/self/environ`).
- **Use template engines** with restricted filesystem access instead of raw `include`/`require` with dynamic paths.

## DON'T

- Use `include($_GET['page'])` or `require($userInput)` in PHP — this is the textbook LFI/RFI vulnerability.
- Construct template paths from user input: `render("templates/" + req.params.template)` in any language or framework.
- Rely on extension checking alone — `../../etc/passwd%00.php` (null byte injection) bypasses extension checks in older PHP versions.
- Allow `php://filter`, `php://input`, `data://`, or `expect://` wrappers — these bypass traditional LFI protections and enable code execution.
- Use blocklist filtering (stripping `../`) instead of canonicalization — encoding bypasses (`%2e%2e%2f`, double encoding) defeat blocklists.
- Log or display file contents in error messages — error messages like "File not found: /etc/shadow" confirm paths exist.

## Common AI Mistakes

- Generating PHP code like `include("pages/" . $_GET['page'] . ".php")` — this is directly exploitable with path traversal.
- Building template rendering that reads files based on URL parameters without path validation.
- Suggesting `basename()` as sufficient protection — `basename()` strips the path but doesn't prevent null byte injection or wrapper attacks on older runtimes.
- Creating Express routes that serve files based on `req.params.filename` using `res.render()` or `fs.readFileSync()`.
- Using Node.js `require()` with user-controlled module paths — this executes arbitrary code.
- Not mentioning PHP stream wrappers (`php://filter/convert.base64-encode/resource=`) as an LFI exploitation technique.
