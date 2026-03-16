# Regex Security (ReDoS Prevention)

## DO

- **Test regex patterns for catastrophic backtracking** using tools like `regex101.com` (debugger), `recheck`, or `safe-regex`. Run tests before deploying.
- **Set timeout limits** on regex execution. In Node.js, use `re2` (linear-time regex engine). In other languages, use built-in timeout mechanisms.
- **Limit input length** before applying regex. A 1MB input string can make even moderate regex patterns run for minutes.
- **Use atomic groups and possessive quantifiers** where supported (`(?>...)`, `a++`) to prevent backtracking.
- **Prefer specific character classes** over `.` with quantifiers. `[a-zA-Z0-9]+` is safer than `.*` followed by a boundary.
- **Use the `re2` library** (Google RE2) in production for user-supplied patterns — it guarantees linear-time matching with no backtracking.
- **Validate email, URLs, and other structured data** with purpose-built parsers, not complex regex patterns.

## DON'T

- Use nested quantifiers: `(a+)+`, `(a*)*`, `(a|b)*a(a|b)*`. These cause exponential backtracking on non-matching inputs.
- Apply regex to unbounded user input without length limits. Even safe patterns degrade on very long strings.
- Let users supply arbitrary regex patterns to your search/filter features without sandboxing (use RE2 or a timeout wrapper).
- Use `.*` in the middle of a pattern with backtracking anchors. The engine tries every possible split point.
- Rely on regex for HTML/XML parsing. Use a proper parser — regex on nested structures is both unsafe and unreliable.
- Write validation regex without testing against adversarial inputs (e.g., `aaaaaaaaaaaaaaaa!` against `^(a+)+$`).

## Common AI Mistakes

- Generating email validation regex like `^([a-zA-Z0-9_.+-]+)+@...` with nested quantifiers that cause ReDoS.
- Using `(.+)+` or `(\s*)*` patterns that have exponential backtracking on non-matching inputs.
- Not setting input length limits before regex matching — applying complex patterns to multi-MB request bodies.
- Suggesting regex for HTML parsing: `/<div.*>(.*)<\/div>/` instead of using a DOM parser.
- Providing regex patterns without testing them against worst-case adversarial inputs.
