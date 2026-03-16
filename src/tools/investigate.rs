use crate::mcp::protocol::{Content, ToolCallResult, ToolDefinition};
use crate::AppState;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Instant;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "firebreak_fetch".into(),
            description: "Fetch any URL and get the full HTTP response (status, headers, body). Use to inspect any endpoint, script, or API response in detail.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "URL to fetch" },
                    "method": { "type": "string", "description": "HTTP method (default GET)" },
                    "headers": { "type": "object", "description": "Custom headers as key-value pairs" },
                    "body": { "type": "string", "description": "Request body" }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "firebreak_analyze_page".into(),
            description: "Deep HTML analysis of a page. Returns all forms, scripts, meta tags, links, iframes, hidden fields. Use when you need to understand what a page does and what data it collects.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "URL of the page to analyze" }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "firebreak_analyze_js".into(),
            description: "Analyze a JavaScript file for security indicators. Extracts WebSocket URLs, API endpoints, redirects, localStorage usage, anti-detection patterns, obfuscation. Use when you find suspicious scripts.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "URL of the JavaScript file" }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "firebreak_probe".into(),
            description: "Send a custom HTTP request with any method, headers, and body. Use to test specific behaviors like CORS, auth bypass, form submission, or WebSocket upgrade.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "URL to probe" },
                    "method": { "type": "string", "description": "HTTP method" },
                    "headers": { "type": "object", "description": "Custom headers" },
                    "body": { "type": "string", "description": "Request body" },
                    "follow_redirects": { "type": "boolean", "description": "Follow redirects (default false)" }
                },
                "required": ["url", "method"]
            }),
        },
        ToolDefinition {
            name: "firebreak_domain_info".into(),
            description: "Get domain intelligence: DNS records, SSL info, subdomains, registration hints. Use at the start of an investigation to understand the target's infrastructure.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Domain name to investigate" }
                },
                "required": ["domain"]
            }),
        },
        ToolDefinition {
            name: "firebreak_extract_forms".into(),
            description: "Extract and classify all forms on a page. Identifies login, payment, OTP, crypto wallet, and data collection forms. Use to understand what data a site collects.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "URL of the page" }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "firebreak_extract_scripts".into(),
            description: "Extract all inline and external scripts from a page with their content. Use to find WebSocket C2, referrer spoofing, anti-detection, and data exfiltration logic.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "URL of the page" }
                },
                "required": ["url"]
            }),
        },
    ]
}

pub async fn call(name: &str, args: &Value, state: &AppState) -> ToolCallResult {
    match name {
        "firebreak_fetch" => fetch(args, state).await,
        "firebreak_analyze_page" => analyze_page(args, state).await,
        "firebreak_analyze_js" => analyze_js(args, state).await,
        "firebreak_probe" => probe(args, state).await,
        "firebreak_domain_info" => domain_info(args, state).await,
        "firebreak_extract_forms" => extract_forms(args, state).await,
        "firebreak_extract_scripts" => extract_scripts(args, state).await,
        _ => text_result(format!("Unknown investigate tool: {name}"), true),
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> &'a str {
    args.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

fn bool_arg(args: &Value, key: &str, default: bool) -> bool {
    args.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

fn headers_arg(args: &Value) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(obj) = args.get("headers").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                map.insert(k.clone(), s.to_string());
            }
        }
    }
    map
}

fn text_result(text: String, is_error: bool) -> ToolCallResult {
    ToolCallResult {
        content: vec![Content::Text { text }],
        is_error: if is_error { Some(true) } else { None },
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...[truncated, {} total]", &s[..max], s.len())
    }
}

async fn do_request(
    state: &AppState,
    url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    follow_redirects: bool,
) -> Result<(u16, Vec<(String, String)>, String, Vec<String>, u128), String> {
    if !state.safety.check_scope(url) {
        return Err(format!("URL out of scope: {url}"));
    }
    state.safety.acquire_rate_limit().await;

    let client = if follow_redirects {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(false)
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .map_err(|e| e.to_string())?
    } else {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(false)
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?
    };

    let m = match method.to_uppercase().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        other => reqwest::Method::from_bytes(other.as_bytes()).map_err(|e| e.to_string())?,
    };

    let mut builder = client.request(m, url);
    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    if let Some(b) = body {
        builder = builder.body(b.to_string());
    }

    let start = Instant::now();
    let resp = builder.send().await.map_err(|e| e.to_string())?;
    let elapsed = start.elapsed().as_millis();

    let status = resp.status().as_u16();
    let resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let mut redirects = Vec::new();
    if !follow_redirects {
        if let Some(loc) = resp.headers().get("location") {
            if let Ok(s) = loc.to_str() {
                redirects.push(s.to_string());
            }
        }
    }

    let body_text = resp.text().await.unwrap_or_default();
    Ok((status, resp_headers, body_text, redirects, elapsed))
}

async fn fetch_body(state: &AppState, url: &str) -> Result<String, String> {
    let headers = HashMap::new();
    let (_, _, body, _, _) = do_request(state, url, "GET", &headers, None, true).await?;
    Ok(body)
}

// --- Tool implementations ---

async fn fetch(args: &Value, state: &AppState) -> ToolCallResult {
    let url = str_arg(args, "url");
    let method = args.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
    let headers = headers_arg(args);
    let body = args.get("body").and_then(|v| v.as_str());

    match do_request(state, url, method, &headers, body, false).await {
        Err(e) => text_result(format!("Error: {e}"), true),
        Ok((status, resp_headers, body_text, redirects, elapsed)) => {
            let mut out = String::new();
            out.push_str("## HTTP Response\n\n");
            out.push_str(&format!("**Status**: {status}\n"));
            out.push_str(&format!("**Time**: {elapsed}ms\n\n"));

            if !redirects.is_empty() {
                out.push_str("**Redirects**:\n");
                for r in &redirects {
                    out.push_str(&format!("- {r}\n"));
                }
                out.push('\n');
            }

            out.push_str("### Headers\n\n");
            for (k, v) in &resp_headers {
                out.push_str(&format!("- `{k}`: `{v}`\n"));
            }

            out.push_str(&format!("\n### Body ({} bytes)\n\n```\n{}\n```\n", body_text.len(), truncate(&body_text, 5000)));
            text_result(out, false)
        }
    }
}

async fn analyze_page(args: &Value, state: &AppState) -> ToolCallResult {
    let url = str_arg(args, "url");
    let html = match fetch_body(state, url).await {
        Ok(h) => h,
        Err(e) => return text_result(format!("Error fetching page: {e}"), true),
    };

    let mut out = format!("## Page Analysis: {url}\n\n**Size**: {} bytes\n\n", html.len());

    // Title
    if let Some(cap) = regex_find(r"(?i)<title[^>]*>([\s\S]*?)</title>", &html) {
        out.push_str(&format!("**Title**: {}\n\n", cap.trim()));
    }

    // Meta tags
    let metas = regex_find_all(r#"(?i)<meta\s+[^>]*>"#, &html);
    if !metas.is_empty() {
        out.push_str("### Meta Tags\n\n");
        for m in &metas {
            let name = extract_attr(m, "name")
                .or_else(|| extract_attr(m, "property"))
                .or_else(|| extract_attr(m, "http-equiv"))
                .unwrap_or_default();
            let content = extract_attr(m, "content").unwrap_or_default();
            if !name.is_empty() || !content.is_empty() {
                out.push_str(&format!("- `{name}` = `{content}`\n"));
            }
        }
        out.push('\n');
    }

    // Forms
    let forms = regex_find_all(r"(?is)<form\b[^>]*>.*?</form>", &html);
    if !forms.is_empty() {
        out.push_str(&format!("### Forms ({})\n\n", forms.len()));
        for (i, form) in forms.iter().enumerate() {
            let action = extract_attr(form, "action").unwrap_or_else(|| "[none]".into());
            let method = extract_attr(form, "method").unwrap_or_else(|| "GET".into());
            out.push_str(&format!("**Form {}**: `{}` `{}`\n", i + 1, method.to_uppercase(), action));
            let inputs = regex_find_all(r"(?i)<input\b[^>]*>", form);
            for inp in &inputs {
                let name = extract_attr(inp, "name").unwrap_or_default();
                let typ = extract_attr(inp, "type").unwrap_or_else(|| "text".into());
                let req = extract_attr(inp, "required").is_some() || inp.contains("required");
                let ac = extract_attr(inp, "autocomplete").unwrap_or_default();
                out.push_str(&format!("  - input: name=`{name}` type=`{typ}`{}{}\n",
                    if req { " **required**" } else { "" },
                    if ac.is_empty() { String::new() } else { format!(" autocomplete=`{ac}`") }
                ));
            }
            out.push('\n');
        }
    }

    // Scripts
    let scripts = regex_find_all(r"(?is)<script\b[^>]*>[\s\S]*?</script>", &html);
    let script_srcs = regex_find_all(r#"(?i)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>"#, &html);
    if !scripts.is_empty() || !script_srcs.is_empty() {
        out.push_str(&format!("### Scripts ({})\n\n", scripts.len()));
        for s in &scripts {
            if let Some(src) = extract_attr(s, "src") {
                out.push_str(&format!("- External: `{src}`\n"));
            } else {
                let content = regex_find(r"(?is)<script[^>]*>([\s\S]*?)</script>", s).unwrap_or_default();
                let trimmed = content.trim();
                if !trimmed.is_empty() {
                    out.push_str(&format!("- Inline ({} chars): `{}`\n", trimmed.len(), truncate(trimmed, 500)));
                }
            }
        }
        out.push('\n');
    }

    // Link tags
    let links = regex_find_all(r#"(?i)<link\b[^>]*>"#, &html);
    if !links.is_empty() {
        out.push_str("### Link Tags\n\n");
        for l in &links {
            let rel = extract_attr(l, "rel").unwrap_or_default();
            let href = extract_attr(l, "href").unwrap_or_default();
            out.push_str(&format!("- rel=`{rel}` href=`{href}`\n"));
        }
        out.push('\n');
    }

    // Iframes
    let iframes = regex_find_all(r#"(?i)<iframe\b[^>]*>"#, &html);
    if !iframes.is_empty() {
        out.push_str("### Iframes\n\n");
        for f in &iframes {
            let src = extract_attr(f, "src").unwrap_or_else(|| "[none]".into());
            out.push_str(&format!("- `{src}`\n"));
        }
        out.push('\n');
    }

    // Hidden inputs
    let hidden = regex_find_all(r#"(?i)<input\b[^>]*type\s*=\s*["']hidden["'][^>]*>"#, &html);
    if !hidden.is_empty() {
        out.push_str("### Hidden Fields\n\n");
        for h in &hidden {
            let name = extract_attr(h, "name").unwrap_or_default();
            let value = extract_attr(h, "value").unwrap_or_default();
            out.push_str(&format!("- name=`{name}` value=`{}`\n", truncate(&value, 100)));
        }
        out.push('\n');
    }

    // External links
    let anchors = regex_find_all(r#"(?i)<a\b[^>]*href\s*=\s*["'](https?://[^"']+)["'][^>]*>"#, &html);
    if !anchors.is_empty() {
        let url_parsed = url::Url::parse(url).ok();
        let host = url_parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("");
        let external: Vec<&String> = anchors.iter().filter(|a| {
            url::Url::parse(a).ok().and_then(|u| u.host_str().map(|h| h.to_string())).map(|h| h != host).unwrap_or(false)
        }).collect();
        if !external.is_empty() {
            out.push_str("### External Links\n\n");
            for e in &external {
                out.push_str(&format!("- `{e}`\n"));
            }
            out.push('\n');
        }
    }

    text_result(out, false)
}

async fn analyze_js(args: &Value, state: &AppState) -> ToolCallResult {
    let url = str_arg(args, "url");
    let js = match fetch_body(state, url).await {
        Ok(h) => h,
        Err(e) => return text_result(format!("Error fetching JS: {e}"), true),
    };

    let mut out = format!("## JS Analysis: {url}\n\n**Size**: {} bytes\n\n", js.len());

    let sections: Vec<(&str, &str)> = vec![
        ("URLs Found", r#"["'](https?://[^\s"'<>]+)["']"#),
        ("WebSocket URLs", r#"["'](wss?://[^\s"'<>]+)["']"#),
        ("fetch() Calls", r#"fetch\s*\(\s*["'`]([^"'`]+)["'`]"#),
        ("axios Calls", r#"axios\.\w+\s*\(\s*["'`]([^"'`]+)["'`]"#),
        ("XMLHttpRequest open()", r#"\.open\s*\(\s*["']\w+["']\s*,\s*["'`]([^"'`]+)["'`]"#),
        ("WebSocket Constructors", r#"new\s+WebSocket\s*\(\s*["'`]([^"'`]+)["'`]"#),
        ("document.referrer Usage", r#"document\.referrer"#),
        ("localStorage Usage", r#"localStorage\.\w+"#),
        ("sessionStorage Usage", r#"sessionStorage\.\w+"#),
        ("window.location Assignments", r#"window\.location\s*[=.]"#),
        ("history.pushState/replaceState", r#"history\.(pushState|replaceState)"#),
        ("eval() Calls", r#"eval\s*\("#),
        ("Function() Calls", r#"new\s+Function\s*\("#),
        ("postMessage Usage", r#"\.postMessage\s*\("#),
        ("Event Listeners", r#"addEventListener\s*\(\s*["'](\w+)["']"#),
        ("Potential API Keys/Secrets", r#"(?i)(api[_-]?key|secret|token|password|auth)\s*[:=]\s*["'`]([^"'`]{8,})["'`]"#),
    ];

    for (label, pattern) in &sections {
        let matches = regex_find_all(pattern, &js);
        if !matches.is_empty() {
            out.push_str(&format!("### {label}\n\n"));
            let mut seen = std::collections::HashSet::new();
            for m in matches.iter().take(50) {
                if seen.insert(m.clone()) {
                    out.push_str(&format!("- `{}`\n", truncate(m, 200)));
                }
            }
            out.push('\n');
        }
    }

    // Comments
    let line_comments = regex_find_all(r"//[^\n]{3,}", &js);
    let block_comments = regex_find_all(r"/\*[\s\S]*?\*/", &js);
    if !line_comments.is_empty() || !block_comments.is_empty() {
        out.push_str("### Comments\n\n");
        for c in line_comments.iter().chain(block_comments.iter()).take(30) {
            out.push_str(&format!("- `{}`\n", truncate(c.trim(), 200)));
        }
        out.push('\n');
    }

    // Obfuscation indicators
    let mut obf = Vec::new();
    if regex_find(r"atob\s*\(", &js).is_some() { obf.push("atob() (base64 decode)"); }
    if regex_find(r"btoa\s*\(", &js).is_some() { obf.push("btoa() (base64 encode)"); }
    if regex_find(r"String\.fromCharCode", &js).is_some() { obf.push("String.fromCharCode"); }
    if regex_find(r"\\x[0-9a-fA-F]{2}", &js).is_some() { obf.push("Hex-encoded strings"); }
    if regex_find(r"[A-Za-z0-9+/=]{50,}", &js).is_some() { obf.push("Long base64-like strings"); }
    if regex_find(r"unescape\s*\(", &js).is_some() { obf.push("unescape()"); }
    if !obf.is_empty() {
        out.push_str("### Obfuscation Indicators\n\n");
        for o in &obf {
            out.push_str(&format!("- {o}\n"));
        }
        out.push('\n');
    }

    text_result(out, false)
}

async fn probe(args: &Value, state: &AppState) -> ToolCallResult {
    let url = str_arg(args, "url");
    let method = str_arg(args, "method");
    let headers = headers_arg(args);
    let body = args.get("body").and_then(|v| v.as_str());
    let follow = bool_arg(args, "follow_redirects", false);

    match do_request(state, url, method, &headers, body, follow).await {
        Err(e) => text_result(format!("Error: {e}"), true),
        Ok((status, resp_headers, body_text, redirects, elapsed)) => {
            let mut out = format!("## Probe Response\n\n**{method}** `{url}`\n**Status**: {status}\n**Time**: {elapsed}ms\n\n");

            if !redirects.is_empty() {
                out.push_str("**Redirects**:\n");
                for r in &redirects {
                    out.push_str(&format!("- {r}\n"));
                }
                out.push('\n');
            }

            out.push_str("### Response Headers\n\n");
            for (k, v) in &resp_headers {
                out.push_str(&format!("- `{k}`: `{v}`\n"));
            }

            out.push_str(&format!("\n### Body ({} bytes)\n\n```\n{}\n```\n", body_text.len(), truncate(&body_text, 5000)));
            text_result(out, false)
        }
    }
}

async fn domain_info(args: &Value, state: &AppState) -> ToolCallResult {
    let domain = str_arg(args, "domain");
    if domain.is_empty() {
        return text_result("Error: domain is required".into(), true);
    }

    let mut out = format!("## Domain Intelligence: {domain}\n\n");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    // DNS lookups via Google DNS API
    let dns_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"];
    out.push_str("### DNS Records\n\n");
    for dtype in &dns_types {
        let dns_url = format!("https://dns.google/resolve?name={domain}&type={dtype}");
        if let Ok(resp) = client.get(&dns_url).send().await {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
                    if !answers.is_empty() {
                        out.push_str(&format!("**{dtype}**:\n"));
                        for ans in answers.iter().take(10) {
                            let data = ans.get("data").and_then(|d| d.as_str()).unwrap_or("");
                            out.push_str(&format!("- `{data}`\n"));
                        }
                    }
                }
            }
        }
    }
    out.push('\n');

    // Main page headers (scope check)
    let main_url = format!("https://{domain}");
    if state.safety.check_scope(&main_url) {
        state.safety.acquire_rate_limit().await;
        out.push_str("### Main Page Response Headers\n\n");
        match state.engine.client().get(&main_url).send().await {
            Ok(resp) => {
                out.push_str(&format!("**Status**: {}\n", resp.status().as_u16()));
                for (k, v) in resp.headers().iter() {
                    out.push_str(&format!("- `{k}`: `{}`\n", v.to_str().unwrap_or("")));
                }
            }
            Err(e) => out.push_str(&format!("Error: {e}\n")),
        }
        out.push('\n');

        // security.txt
        state.safety.acquire_rate_limit().await;
        let sectxt_url = format!("https://{domain}/.well-known/security.txt");
        out.push_str("### security.txt\n\n");
        match client.get(&sectxt_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let body = resp.text().await.unwrap_or_default();
                out.push_str(&format!("```\n{}\n```\n\n", truncate(&body, 2000)));
            }
            _ => out.push_str("Not found\n\n"),
        }

        // robots.txt
        state.safety.acquire_rate_limit().await;
        let robots_url = format!("https://{domain}/robots.txt");
        out.push_str("### robots.txt\n\n");
        match client.get(&robots_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let body = resp.text().await.unwrap_or_default();
                out.push_str(&format!("```\n{}\n```\n\n", truncate(&body, 2000)));
            }
            _ => out.push_str("Not found\n\n"),
        }
    }

    // Subdomain checks
    let subdomains = ["www", "api", "admin", "mail", "staging", "dev"];
    out.push_str("### Subdomain Checks\n\n");
    for sub in &subdomains {
        let sub_url = format!("https://dns.google/resolve?name={sub}.{domain}&type=A");
        if let Ok(resp) = client.get(&sub_url).send().await {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
                    if !answers.is_empty() {
                        let ip = answers[0].get("data").and_then(|d| d.as_str()).unwrap_or("?");
                        out.push_str(&format!("- `{sub}.{domain}` -> `{ip}`\n"));
                    }
                } else {
                    out.push_str(&format!("- `{sub}.{domain}` -> not found\n"));
                }
            }
        }
    }
    out.push('\n');

    text_result(out, false)
}

async fn extract_forms(args: &Value, state: &AppState) -> ToolCallResult {
    let url = str_arg(args, "url");
    let html = match fetch_body(state, url).await {
        Ok(h) => h,
        Err(e) => return text_result(format!("Error fetching page: {e}"), true),
    };

    let forms = regex_find_all(r"(?is)<form\b[^>]*>.*?</form>", &html);
    if forms.is_empty() {
        return text_result(format!("## Form Extraction: {url}\n\nNo forms found."), false);
    }

    let mut out = format!("## Form Extraction: {url}\n\n**Forms found**: {}\n\n", forms.len());

    for (i, form) in forms.iter().enumerate() {
        let action = extract_attr(form, "action").unwrap_or_else(|| "[none]".into());
        let method = extract_attr(form, "method").unwrap_or_else(|| "GET".into());

        out.push_str(&format!("### Form {} — `{}` `{}`\n\n", i + 1, method.to_uppercase(), action));

        // Inputs
        let inputs = regex_find_all(r"(?i)<input\b[^>]*>", form);
        let mut has_password = false;
        let mut has_otp = false;
        let mut has_card = false;
        let mut has_crypto = false;
        let mut has_upload = false;

        if !inputs.is_empty() {
            out.push_str("**Input Fields**:\n");
            for inp in &inputs {
                let name = extract_attr(inp, "name").unwrap_or_default();
                let typ = extract_attr(inp, "type").unwrap_or_else(|| "text".into());
                let id = extract_attr(inp, "id").unwrap_or_default();
                let placeholder = extract_attr(inp, "placeholder").unwrap_or_default();
                let pattern = extract_attr(inp, "pattern").unwrap_or_default();
                let ac = extract_attr(inp, "autocomplete").unwrap_or_default();
                let value = extract_attr(inp, "value").unwrap_or_default();
                let req = inp.contains("required");

                let name_lower = name.to_lowercase();
                let placeholder_lower = placeholder.to_lowercase();
                if typ == "password" { has_password = true; }
                if name_lower.contains("otp") || name_lower.contains("code") || name_lower.contains("2fa") || name_lower.contains("totp") { has_otp = true; }
                if name_lower.contains("card") || name_lower.contains("cvv") || name_lower.contains("ccnum") || ac.contains("cc-") { has_card = true; }
                if name_lower.contains("seed") || name_lower.contains("mnemonic") || name_lower.contains("passphrase") || name_lower.contains("wallet")
                    || placeholder_lower.contains("seed") || placeholder_lower.contains("mnemonic") || placeholder_lower.contains("recovery phrase") { has_crypto = true; }
                if typ == "file" && (name_lower.contains("selfie") || name_lower.contains("photo") || name_lower.contains("id")) { has_upload = true; }

                let mut detail = format!("  - `{name}` type=`{typ}`");
                if !id.is_empty() { detail.push_str(&format!(" id=`{id}`")); }
                if req { detail.push_str(" **required**"); }
                if !placeholder.is_empty() { detail.push_str(&format!(" placeholder=`{placeholder}`")); }
                if !pattern.is_empty() { detail.push_str(&format!(" pattern=`{pattern}`")); }
                if !ac.is_empty() { detail.push_str(&format!(" autocomplete=`{ac}`")); }
                if !value.is_empty() && typ == "hidden" { detail.push_str(&format!(" value=`{}`", truncate(&value, 60))); }
                out.push_str(&format!("{detail}\n"));
            }
            out.push('\n');
        }

        // Selects
        let selects = regex_find_all(r"(?is)<select\b[^>]*>.*?</select>", form);
        if !selects.is_empty() {
            out.push_str("**Select Fields**:\n");
            for sel in &selects {
                let name = extract_attr(sel, "name").unwrap_or_default();
                let options = regex_find_all(r"(?is)<option\b[^>]*>(.*?)</option>", sel);
                out.push_str(&format!("  - `{name}` ({} options)\n", options.len()));
            }
            out.push('\n');
        }

        // Textareas
        let textareas = regex_find_all(r"(?is)<textarea\b[^>]*>", form);
        if !textareas.is_empty() {
            out.push_str("**Textarea Fields**:\n");
            for ta in &textareas {
                let name = extract_attr(ta, "name").unwrap_or_default();
                out.push_str(&format!("  - `{name}`\n"));
            }
            out.push('\n');
        }

        // Classification
        let mut classifications = Vec::new();
        if has_crypto { classifications.push("**CRYPTO THEFT** (seed/mnemonic/wallet field detected)"); }
        if has_card { classifications.push("Payment/Credit Card"); }
        if has_upload { classifications.push("Identity Theft (selfie/photo upload)"); }
        if has_otp { classifications.push("OTP / 2FA"); }
        if has_password {
            let has_email = inputs.iter().any(|i| {
                let n = extract_attr(i, "name").unwrap_or_default().to_lowercase();
                let t = extract_attr(i, "type").unwrap_or_default();
                n.contains("email") || n.contains("user") || t == "email"
            });
            let field_count = inputs.iter().filter(|i| {
                let t = extract_attr(i, "type").unwrap_or_else(|| "text".into());
                t != "hidden" && t != "submit"
            }).count();
            if has_email && field_count > 3 { classifications.push("Registration"); }
            else { classifications.push("Login"); }
        }
        if classifications.is_empty() {
            let has_search = inputs.iter().any(|i| extract_attr(i, "type").map(|t| t == "search").unwrap_or(false)
                || extract_attr(i, "name").map(|n| n.to_lowercase().contains("search") || n == "q").unwrap_or(false));
            if has_search { classifications.push("Search"); }
            else { classifications.push("Data Collection / Contact"); }
        }

        out.push_str(&format!("**Classification**: {}\n\n", classifications.join(", ")));
    }

    text_result(out, false)
}

async fn extract_scripts(args: &Value, state: &AppState) -> ToolCallResult {
    let url = str_arg(args, "url");
    let html = match fetch_body(state, url).await {
        Ok(h) => h,
        Err(e) => return text_result(format!("Error fetching page: {e}"), true),
    };

    let scripts = regex_find_all(r"(?is)<script\b[^>]*>[\s\S]*?</script>", &html);
    if scripts.is_empty() {
        return text_result(format!("## Script Extraction: {url}\n\nNo scripts found."), false);
    }

    let mut out = format!("## Script Extraction: {url}\n\n**Total scripts**: {}\n\n", scripts.len());

    let mut ext_idx = 0;
    let mut inline_idx = 0;

    for s in &scripts {
        if let Some(src) = extract_attr(s, "src") {
            ext_idx += 1;
            out.push_str(&format!("### External Script {ext_idx}: `{src}`\n\n"));

            let abs_url = resolve_url(url, &src);
            if state.safety.check_scope(&abs_url) {
                state.safety.acquire_rate_limit().await;
                match state.engine.client().get(&abs_url).send().await {
                    Ok(resp) => {
                        let body = resp.text().await.unwrap_or_default();
                        out.push_str(&format!("**Size**: {} bytes\n", body.len()));
                        out.push_str(&format!("```javascript\n{}\n```\n\n", truncate(&body, 1000)));
                        append_js_summary(&body, &mut out);
                    }
                    Err(e) => out.push_str(&format!("Fetch error: {e}\n\n")),
                }
            } else {
                out.push_str("(out of scope, not fetched)\n\n");
            }
        } else {
            let content = regex_find(r"(?is)<script[^>]*>([\s\S]*?)</script>", s).unwrap_or_default();
            let trimmed = content.trim();
            if trimmed.is_empty() { continue; }
            inline_idx += 1;
            out.push_str(&format!("### Inline Script {inline_idx} ({} chars)\n\n", trimmed.len()));
            out.push_str(&format!("```javascript\n{}\n```\n\n", truncate(trimmed, 2000)));
            append_js_summary(trimmed, &mut out);
        }
    }

    text_result(out, false)
}

fn append_js_summary(js: &str, out: &mut String) {
    let checks: Vec<(&str, &str)> = vec![
        ("URLs", r#"["'](https?://[^\s"'<>]+)["']"#),
        ("WebSocket", r#"wss?://"#),
        ("localStorage", r#"localStorage\."#),
        ("sessionStorage", r#"sessionStorage\."#),
        ("window.location", r#"window\.location"#),
        ("eval/Function", r#"(eval\s*\(|new\s+Function\s*\()"#),
        ("postMessage", r#"\.postMessage\s*\("#),
        ("fetch/XHR", r#"(fetch\s*\(|XMLHttpRequest|axios\.)"#),
    ];
    let mut found = Vec::new();
    for (label, pattern) in &checks {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(js) {
                found.push(*label);
            }
        }
    }
    if !found.is_empty() {
        out.push_str(&format!("**Indicators**: {}\n\n", found.join(", ")));
    }
}

// --- Regex helpers ---

fn regex_find(pattern: &str, text: &str) -> Option<String> {
    Regex::new(pattern).ok().and_then(|re| {
        re.captures(text).map(|c| {
            c.get(1).map(|m| m.as_str().to_string()).unwrap_or_else(|| c[0].to_string())
        })
    })
}

fn regex_find_all(pattern: &str, text: &str) -> Vec<String> {
    let Ok(re) = Regex::new(pattern) else { return vec![] };
    re.captures_iter(text)
        .map(|c| c.get(1).map(|m| m.as_str().to_string()).unwrap_or_else(|| c[0].to_string()))
        .collect()
}

fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let pattern = format!(r#"(?i)\b{}\s*=\s*["']([^"']*)["']"#, regex::escape(attr));
    Regex::new(&pattern).ok().and_then(|re| {
        re.captures(tag).map(|c| c[1].to_string())
    })
}

fn resolve_url(base: &str, relative: &str) -> String {
    if relative.starts_with("http://") || relative.starts_with("https://") {
        return relative.to_string();
    }
    if let Ok(base_url) = url::Url::parse(base) {
        if let Ok(resolved) = base_url.join(relative) {
            return resolved.to_string();
        }
    }
    relative.to_string()
}
