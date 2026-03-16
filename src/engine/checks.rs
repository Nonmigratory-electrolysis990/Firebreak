use crate::safety::Safety;
use crate::types::*;
use reqwest::Client;
use super::{make_finding, truncate_body};

async fn safe_get(client: &Client, url: &str, safety: &Safety) -> Option<reqwest::Response> {
    if !safety.check_scope(url) {
        return None;
    }
    safety.acquire_rate_limit().await;
    safety.log_action("http_request", url, "GET request");
    client.get(url).send().await.ok()
}

async fn safe_get_with_body(client: &Client, url: &str, safety: &Safety) -> Option<(reqwest::StatusCode, String, String)> {
    let resp = safe_get(client, url, safety).await?;
    let status = resp.status();
    let content_type = resp.headers().get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    let body = resp.text().await.unwrap_or_default();
    Some((status, content_type, body))
}

fn validate_sensitive_path_content(path: &str, content_type: &str, body: &str) -> bool {
    let body_lower = body.to_lowercase();
    match path {
        "/.env" => {
            if content_type.contains("text/html") || content_type.contains("application/json") {
                return false;
            }
            let env_line = regex::Regex::new(r"[A-Z_]+=").unwrap();
            env_line.is_match(body)
        }
        "/.git/config" => {
            if content_type.contains("text/html") || content_type.contains("application/json") {
                return false;
            }
            body.contains("[core]") || body.contains("[remote")
        }
        "/admin" => {
            if content_type.contains("application/json") {
                return false;
            }
            let keywords = ["<form", "login", "password", "admin", "dashboard"];
            keywords.iter().any(|kw| body_lower.contains(kw))
        }
        "/graphql" => {
            if content_type.contains("application/json") {
                let has_graphql_keys = body_lower.contains("\"data\"") || body_lower.contains("\"errors\"");
                return has_graphql_keys;
            }
            body_lower.contains("graphql")
        }
        "/swagger" | "/api-docs" => {
            body_lower.contains("swagger") || body_lower.contains("openapi")
        }
        "/debug" => {
            let keywords = ["debug", "traceback", "stack trace", "stacktrace"];
            keywords.iter().any(|kw| body_lower.contains(kw))
        }
        "/api" => true,
        _ => true,
    }
}

fn capture_response(resp: &reqwest::Response, method: &str, url: &str) -> HttpRecord {
    HttpRecord {
        method: method.to_string(),
        url: url.to_string(),
        headers: resp.headers().iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect(),
        body: None,
        status: Some(resp.status().as_u16()),
    }
}

fn request_record(method: &str, url: &str, extra_headers: &[(String, String)]) -> HttpRecord {
    HttpRecord {
        method: method.to_string(),
        url: url.to_string(),
        headers: extra_headers.to_vec(),
        body: None,
        status: None,
    }
}

pub async fn check_security_headers(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let resp = match safe_get(client, target, safety).await {
        Some(r) => r,
        None => return vec![],
    };

    let req_rec = request_record("GET", target, &[]);
    let resp_rec = capture_response(&resp, "GET", target);
    let header_names: Vec<String> = resp.headers().keys().map(|k| k.to_string().to_lowercase()).collect();

    let required: &[(&str, &str, &str)] = &[
        ("strict-transport-security", "Missing HSTS header", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ("x-content-type-options", "Missing X-Content-Type-Options header", "Add X-Content-Type-Options: nosniff"),
        ("x-frame-options", "Missing X-Frame-Options header", "Add X-Frame-Options: DENY or SAMEORIGIN"),
        ("content-security-policy", "Missing Content-Security-Policy header", "Define a Content-Security-Policy that restricts resource loading"),
    ];

    let mut findings = Vec::new();
    for (header, title, fix) in required {
        if header_names.iter().any(|h| h == *header) {
            continue;
        }
        findings.push(make_finding(
            "VC-INFRA-003",
            FindingSeverity::Medium,
            title.to_string(),
            format!("Response from {target} is missing the {header} security header"),
            Evidence {
                request: Some(req_rec.clone()),
                response: Some(resp_rec.clone()),
                detail: format!("{header} header not found in response"),
            },
            fix.to_string(),
        ));
    }
    findings
}

pub async fn check_sensitive_paths(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let paths = ["/admin", "/api", "/.env", "/.git/config", "/debug", "/graphql", "/swagger", "/api-docs"];

    let mut findings = Vec::new();
    for path in &paths {
        let url = format!("{base}{path}");
        let (status, content_type, body) = match safe_get_with_body(client, &url, safety).await {
            Some(t) => t,
            None => continue,
        };

        if status.as_u16() != 200 {
            continue;
        }

        if !validate_sensitive_path_content(path, &content_type, &body) {
            continue;
        }

        let (vcvd, severity, title, desc) = match *path {
            "/admin" => ("VC-INFRA-007", FindingSeverity::High, "Exposed admin panel", format!("Admin panel accessible at {url}")),
            "/.env" => ("VC-INFRA-001", FindingSeverity::Critical, "Exposed .env file", format!("Environment file with potential secrets accessible at {url}")),
            "/.git/config" => ("VC-INFRA-001", FindingSeverity::Critical, "Exposed Git configuration", format!("Git config accessible at {url}, may allow repository reconstruction")),
            "/debug" => ("VC-INFRA-001", FindingSeverity::High, "Debug endpoint exposed", format!("Debug endpoint accessible at {url}")),
            "/graphql" => ("VC-DATA-006", FindingSeverity::Medium, "GraphQL endpoint accessible", format!("GraphQL endpoint found at {url}, may allow introspection")),
            "/swagger" | "/api-docs" => ("VC-INFRA-001", FindingSeverity::Medium, "API documentation exposed", format!("API documentation accessible at {url}")),
            "/api" => ("VC-INFRA-007", FindingSeverity::Low, "API root accessible", format!("API root endpoint accessible at {url}")),
            _ => continue,
        };

        let resp_with_body = HttpRecord {
            method: "GET".into(),
            url: url.clone(),
            headers: vec![("content-type".into(), content_type.clone())],
            body: Some(truncate_body(&body)),
            status: Some(status.as_u16()),
        };

        findings.push(make_finding(
            vcvd,
            severity,
            title.to_string(),
            desc,
            Evidence {
                request: Some(request_record("GET", &url, &[])),
                response: Some(resp_with_body),
                detail: format!("{path} returned HTTP 200 with validated content"),
            },
            format!("Restrict access to {path} or remove it from production"),
        ));
    }
    findings
}

pub async fn check_cors(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    if !safety.check_scope(target) {
        return vec![];
    }
    safety.acquire_rate_limit().await;
    safety.log_action("http_request", target, "CORS probe with evil origin");

    let resp = match client.get(target)
        .header("Origin", "https://evil.com")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let acao = resp.headers().get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let allows_creds = resp.headers().get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("") == "true";

    let reflects_evil = acao.contains("evil.com");
    let wildcard_with_creds = acao == "*" && allows_creds;

    if !reflects_evil && !wildcard_with_creds {
        return vec![];
    }

    let detail = if reflects_evil {
        "Server reflects arbitrary Origin header in Access-Control-Allow-Origin"
    } else {
        "Server uses Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"
    };

    vec![make_finding(
        "VC-INFRA-002",
        FindingSeverity::High,
        "Permissive CORS configuration".into(),
        format!("CORS misconfiguration at {target}: {detail}"),
        Evidence {
            request: Some(request_record("GET", target, &[("Origin".into(), "https://evil.com".into())])),
            response: Some(capture_response(&resp, "GET", target)),
            detail: detail.into(),
        },
        "Set specific allowed origins. Never combine * with credentials.".into(),
    )]
}

pub async fn check_tls_redirect(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    if !target.starts_with("https://") {
        return vec![];
    }

    let http_url = target.replacen("https://", "http://", 1);
    if !safety.check_scope(&http_url) {
        return vec![];
    }
    safety.acquire_rate_limit().await;
    safety.log_action("http_request", &http_url, "TLS downgrade check");

    let resp = match client.get(&http_url).send().await {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let status = resp.status().as_u16();
    let location = resp.headers().get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if (300..400).contains(&status) && location.starts_with("https://") {
        return vec![];
    }

    if status < 400 {
        return vec![make_finding(
            "VC-INFRA-006",
            FindingSeverity::Medium,
            "HTTP does not redirect to HTTPS".into(),
            format!("HTTP version of {target} serves content without redirecting to HTTPS"),
            Evidence {
                request: Some(request_record("GET", &http_url, &[])),
                response: Some(capture_response(&resp, "GET", &http_url)),
                detail: format!("HTTP request returned status {status} without HTTPS redirect"),
            },
            "Configure the server to redirect all HTTP requests to HTTPS with a 301.".into(),
        )];
    }

    vec![]
}

pub async fn check_auth_endpoints(client: &Client, target: &str, config: &ScanConfig, safety: &Safety) -> Vec<Finding> {
    if config.credentials.is_empty() {
        return vec![];
    }

    let base = target.trim_end_matches('/');
    let protected = ["/api/users", "/api/admin", "/api/account", "/api/settings", "/api/dashboard"];
    let cred = &config.credentials[0];

    let mut findings = Vec::new();
    for path in &protected {
        let url = format!("{base}{path}");
        if !safety.check_scope(&url) {
            continue;
        }

        safety.acquire_rate_limit().await;
        safety.log_action("http_request", &url, "Auth check: authenticated request");
        let authed = match client.get(&url)
            .basic_auth(&cred.username, Some(&cred.password))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        if authed.status().as_u16() != 200 {
            continue;
        }
        let authed_status = authed.status().as_u16();

        safety.acquire_rate_limit().await;
        safety.log_action("http_request", &url, "Auth check: unauthenticated request");
        let unauthed = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let unauthed_status = unauthed.status().as_u16();
        if unauthed_status != 200 {
            continue;
        }

        let resp_rec = capture_response(&unauthed, "GET", &url);
        let body = unauthed.text().await.unwrap_or_default();
        let mut rr = resp_rec;
        rr.body = Some(truncate_body(&body));

        findings.push(make_finding(
            "VC-AUTH-001",
            FindingSeverity::Critical,
            format!("Missing authentication on {path}"),
            format!("Endpoint {url} returns 200 both with and without credentials"),
            Evidence {
                request: Some(request_record("GET", &url, &[])),
                response: Some(rr),
                detail: format!("Authenticated: {authed_status}, Unauthenticated: {unauthed_status}"),
            },
            "Apply authentication middleware to this endpoint.".into(),
        ));
    }
    findings
}

pub async fn check_idor(client: &Client, target: &str, config: &ScanConfig, safety: &Safety) -> Vec<Finding> {
    if config.credentials.len() < 2 {
        return vec![];
    }

    let base = target.trim_end_matches('/');
    let resource_paths = ["/api/users/1", "/api/orders/1", "/api/account/profile"];
    let cred_a = &config.credentials[0];
    let cred_b = &config.credentials[1];

    let mut findings = Vec::new();
    for path in &resource_paths {
        let url = format!("{base}{path}");
        if !safety.check_scope(&url) {
            continue;
        }

        safety.acquire_rate_limit().await;
        safety.log_action("http_request", &url, "IDOR check: user A");
        let resp_a = match client.get(&url)
            .basic_auth(&cred_a.username, Some(&cred_a.password))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        if resp_a.status().as_u16() != 200 {
            continue;
        }
        let body_a = resp_a.text().await.unwrap_or_default();

        safety.acquire_rate_limit().await;
        safety.log_action("http_request", &url, "IDOR check: user B");
        let resp_b = match client.get(&url)
            .basic_auth(&cred_b.username, Some(&cred_b.password))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        if resp_b.status().as_u16() != 200 {
            continue;
        }
        let body_b = resp_b.text().await.unwrap_or_default();

        if body_a == body_b && !body_a.is_empty() {
            findings.push(make_finding(
                "VC-DATA-001",
                FindingSeverity::Critical,
                format!("Potential IDOR on {path}"),
                format!("Users '{}' ({}) and '{}' ({}) get identical data from {url}",
                    cred_a.username, cred_a.role, cred_b.username, cred_b.role),
                Evidence {
                    request: Some(request_record("GET", &url, &[])),
                    response: Some(HttpRecord {
                        method: "GET".into(),
                        url: url.clone(),
                        headers: vec![],
                        body: Some(truncate_body(&body_b)),
                        status: Some(200),
                    }),
                    detail: format!("Both users received identical {}-byte response", body_a.len()),
                },
                "Add ownership checks: verify the requesting user owns the resource.".into(),
            ));
        }
    }
    findings
}

pub async fn check_info_disclosure(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let probe_paths = ["/", "/api", "/api/health", "/api/status", "/404-not-a-real-page"];

    let patterns: &[(&str, &str, &str)] = &[
        (r"(?i)stack\s*trace", "Stack trace in response", "VC-INFRA-001"),
        (r"(?i)(sql|mysql|postgresql|sqlite)\s*(error|exception|syntax)", "SQL error in response", "VC-INFRA-001"),
        (r"(?i)at\s+\w+\.\w+\s*\(.*:\d+:\d+\)", "JavaScript stack trace in response", "VC-INFRA-001"),
        (r"(?i)traceback\s*\(most recent call", "Python traceback in response", "VC-INFRA-001"),
        (r#"(?i)"version"\s*:\s*"\d+\.\d+""#, "Version number disclosed", "VC-INFRA-001"),
        (r#"(?i)(password|secret|api_key|apikey|token)\s*[:=]\s*['"][^'"]{4,}"#, "Potential secret in response", "VC-FE-001"),
    ];

    let regexes: Vec<(regex::Regex, &str, &str)> = patterns.iter()
        .filter_map(|(pat, desc, vcvd)| regex::Regex::new(pat).ok().map(|r| (r, *desc, *vcvd)))
        .collect();

    let mut findings = Vec::new();
    for path in &probe_paths {
        let url = format!("{base}{path}");
        let resp = match safe_get(client, &url, safety).await {
            Some(r) => r,
            None => continue,
        };

        let status = resp.status().as_u16();
        let header_text: String = resp.headers().iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n");
        let resp_rec = capture_response(&resp, "GET", &url);
        let body = resp.text().await.unwrap_or_default();
        let haystack = format!("{header_text}\n{body}");

        for (re, desc, vcvd) in &regexes {
            if let Some(m) = re.find(&haystack) {
                let snippet = &haystack[m.start()..m.end().min(m.start() + 200)];
                let mut rr = resp_rec.clone();
                rr.body = Some(truncate_body(&body));

                findings.push(make_finding(
                    vcvd,
                    FindingSeverity::Medium,
                    format!("Information disclosure on {path}"),
                    format!("{desc} at {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(rr),
                        detail: format!("Pattern matched (status {status}): {snippet}"),
                    },
                    "Remove detailed error messages and version info from production responses.".into(),
                ));
                break;
            }
        }
    }
    findings
}

pub async fn check_parameter_fuzzing(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');

    let probes: &[(&str, &str, &str)] = &[
        ("'", "sql_injection", "VC-INJ-001"),
        ("\"", "sql_injection", "VC-INJ-001"),
        ("<script>alert(1)</script>", "xss", "VC-INJ-002"),
        ("{{7*7}}", "template_injection", "VC-INJ-007"),
        ("${7*7}", "template_injection", "VC-INJ-007"),
        ("../../../etc/passwd", "path_traversal", "VC-INJ-005"),
    ];

    let error_sigs: &[(&str, &str)] = &[
        (r"(?i)(sql|mysql|postgresql|sqlite)\s*(error|syntax|exception)", "sql_injection"),
        (r"(?i)you have an error in your sql syntax", "sql_injection"),
        (r"(?i)unclosed quotation mark", "sql_injection"),
        (r"49", "template_injection"),
        (r"root:.*:0:0:", "path_traversal"),
    ];

    let sig_regexes: Vec<(regex::Regex, &str)> = error_sigs.iter()
        .filter_map(|(pat, kind)| regex::Regex::new(pat).ok().map(|r| (r, *kind)))
        .collect();

    let test_paths = ["/search", "/api/search", "/api/query", "/api/v1/search"];

    let mut findings = Vec::new();
    for path in &test_paths {
        let baseline_url = format!("{base}{path}?q=test123");
        let (baseline_status, _, baseline_body) = match safe_get_with_body(client, &baseline_url, safety).await {
            Some(t) => (t.0.as_u16(), t.1, t.2),
            None => continue,
        };

        for (payload, attack_type, vcvd) in probes {
            let url = format!("{base}{path}?q={}", minimal_urlencode(payload));
            let (status, _, body) = match safe_get_with_body(client, &url, safety).await {
                Some(t) => (t.0.as_u16(), t.1, t.2),
                None => continue,
            };

            if status == baseline_status && status == 404 {
                continue;
            }

            if *attack_type == "xss" && body.contains(payload) {
                if baseline_body.contains(payload) {
                    continue;
                }
                findings.push(make_finding(
                    vcvd,
                    FindingSeverity::High,
                    format!("Reflected XSS on {path}"),
                    format!("Input reflected without sanitization at {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(HttpRecord {
                            method: "GET".into(),
                            url: url.clone(),
                            headers: vec![],
                            body: Some(truncate_body(&body)),
                            status: Some(status),
                        }),
                        detail: format!("Payload reflected in response (status {status}, baseline {baseline_status})"),
                    },
                    "Sanitize user input before rendering. Use framework auto-escaping.".into(),
                ));
                break;
            }

            if *attack_type == "template_injection" && payload.contains("7*7") && body.contains("49") {
                if baseline_body.contains("49") {
                    continue;
                }
                findings.push(make_finding(
                    vcvd,
                    FindingSeverity::High,
                    format!("Potential template injection on {path}"),
                    format!("Template expression evaluated when fuzzing {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(HttpRecord {
                            method: "GET".into(),
                            url: url.clone(),
                            headers: vec![],
                            body: Some(truncate_body(&body)),
                            status: Some(status),
                        }),
                        detail: format!("Evaluated result '49' found in response (status {status}, baseline {baseline_status})"),
                    },
                    "Use parameterized queries and strict input validation.".into(),
                ));
                break;
            }

            let baseline_has_sig = sig_regexes.iter().any(|(re, kind)| *kind == *attack_type && re.is_match(&baseline_body));
            let matched_sig = sig_regexes.iter().find(|(re, kind)| *kind == *attack_type && re.is_match(&body));

            if matched_sig.is_some() && !baseline_has_sig {
                let status_differs = status != baseline_status;
                if !status_differs && body == baseline_body {
                    continue;
                }
                let severity = if *attack_type == "sql_injection" {
                    FindingSeverity::Critical
                } else {
                    FindingSeverity::High
                };
                findings.push(make_finding(
                    vcvd,
                    severity,
                    format!("Potential {} on {path}", attack_type.replace('_', " ")),
                    format!("Error signature detected when fuzzing {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(HttpRecord {
                            method: "GET".into(),
                            url: url.clone(),
                            headers: vec![],
                            body: Some(truncate_body(&body)),
                            status: Some(status),
                        }),
                        detail: format!("Error response triggered (status {status}, baseline {baseline_status})"),
                    },
                    "Use parameterized queries and strict input validation.".into(),
                ));
                break;
            }
        }
    }
    findings
}

pub async fn check_frontend_exposure(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let mut findings = Vec::new();

    let map_paths = ["/main.js.map", "/app.js.map", "/bundle.js.map", "/static/js/main.js.map"];
    for path in &map_paths {
        let url = format!("{base}{path}");
        let (status, content_type, body) = match safe_get_with_body(client, &url, safety).await {
            Some(t) => t,
            None => continue,
        };
        if status.as_u16() != 200 {
            continue;
        }
        if content_type.contains("text/html") {
            continue;
        }
        let trimmed = body.trim_start();
        if !trimmed.starts_with('{') || !body.contains("\"mappings\"") {
            continue;
        }
        findings.push(make_finding(
            "VC-FE-007",
            FindingSeverity::Low,
            format!("Source map exposed at {path}"),
            format!("JavaScript source map accessible at {url}"),
            Evidence {
                request: Some(request_record("GET", &url, &[])),
                response: Some(HttpRecord {
                    method: "GET".into(),
                    url: url.clone(),
                    headers: vec![("content-type".into(), content_type.clone())],
                    body: Some(truncate_body(&body)),
                    status: Some(status.as_u16()),
                }),
                detail: format!("{path} returned HTTP 200 with valid source map content"),
            },
            "Remove source maps from production or restrict access.".into(),
        ));
    }

    let js_paths = ["/main.js", "/app.js", "/bundle.js", "/static/js/main.js"];
    let secret_sigs: &[(&str, &str)] = &[
        (r"(?i)(sk_live_|sk_test_)[a-zA-Z0-9]{10,}", "Stripe secret key"),
        (r"(?i)AKIA[A-Z0-9]{16}", "AWS access key"),
        (r"(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{20,}", "GitHub token"),
        (r#"(?i)(password|secret|api_key|apikey)\s*[:=]\s*['"][^'"]{8,}"#, "Hardcoded secret"),
        (r#"(?i)service_role['"]?\s*[:=]\s*['"][^'"]{10,}"#, "Supabase service role key"),
    ];

    let secret_regexes: Vec<(regex::Regex, &str)> = secret_sigs.iter()
        .filter_map(|(pat, desc)| regex::Regex::new(pat).ok().map(|r| (r, *desc)))
        .collect();

    for path in &js_paths {
        let url = format!("{base}{path}");
        let resp = match safe_get(client, &url, safety).await {
            Some(r) => r,
            None => continue,
        };
        if resp.status().as_u16() != 200 {
            continue;
        }
        let resp_rec = capture_response(&resp, "GET", &url);
        let body = resp.text().await.unwrap_or_default();

        for (re, desc) in &secret_regexes {
            if let Some(m) = re.find(&body) {
                let snippet = &body[m.start()..m.end().min(m.start() + 50)];
                let mut rr = resp_rec.clone();
                rr.body = Some(truncate_body(&body));
                findings.push(make_finding(
                    "VC-FE-001",
                    FindingSeverity::Critical,
                    format!("{desc} in JavaScript bundle"),
                    format!("Potential secret ({desc}) found in {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(rr),
                        detail: format!("Pattern matched: {snippet}..."),
                    },
                    "Move secrets to server-side environment variables.".into(),
                ));
                break;
            }
        }
    }
    findings
}

pub async fn check_parameter_fuzzing_urls(client: &Client, urls: &[String], safety: &Safety) -> Vec<Finding> {
    let interesting: Vec<&String> = urls.iter()
        .filter(|u| {
            u.contains("/api/") || u.contains("/api?") || u.contains('?')
                || u.contains("/search") || u.contains("/query")
                || u.contains("/graphql") || u.contains("/v1/") || u.contains("/v2/")
        })
        .take(20)
        .collect();

    let probes: &[(&str, &str, &str)] = &[
        ("'", "sql_injection", "VC-INJ-001"),
        ("\"", "sql_injection", "VC-INJ-001"),
        ("<script>alert(1)</script>", "xss", "VC-INJ-002"),
        ("{{7*7}}", "template_injection", "VC-INJ-007"),
        ("${7*7}", "template_injection", "VC-INJ-007"),
        ("../../../etc/passwd", "path_traversal", "VC-INJ-005"),
    ];

    let error_sigs: &[(&str, &str)] = &[
        (r"(?i)(sql|mysql|postgresql|sqlite)\s*(error|syntax|exception)", "sql_injection"),
        (r"(?i)you have an error in your sql syntax", "sql_injection"),
        (r"(?i)unclosed quotation mark", "sql_injection"),
        (r"49", "template_injection"),
        (r"root:.*:0:0:", "path_traversal"),
    ];

    let sig_regexes: Vec<(regex::Regex, &str)> = error_sigs.iter()
        .filter_map(|(pat, kind)| regex::Regex::new(pat).ok().map(|r| (r, *kind)))
        .collect();

    let mut findings = Vec::new();
    for base_url in &interesting {
        let (path_part, _existing_query) = match base_url.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (base_url.as_str(), None),
        };

        let baseline_url = format!("{path_part}?q=test123");
        let (baseline_status, _, baseline_body) = match safe_get_with_body(client, &baseline_url, safety).await {
            Some(t) => (t.0.as_u16(), t.1, t.2),
            None => continue,
        };

        for (payload, attack_type, vcvd) in probes {
            let url = format!("{}?q={}", path_part, minimal_urlencode(payload));
            let (status, _, body) = match safe_get_with_body(client, &url, safety).await {
                Some(t) => (t.0.as_u16(), t.1, t.2),
                None => continue,
            };

            if status == baseline_status && status == 404 {
                continue;
            }

            if *attack_type == "xss" && body.contains(payload) {
                if baseline_body.contains(payload) {
                    continue;
                }
                findings.push(make_finding(
                    vcvd,
                    FindingSeverity::High,
                    format!("Reflected XSS on {path_part}"),
                    format!("Input reflected without sanitization at {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(HttpRecord {
                            method: "GET".into(),
                            url: url.clone(),
                            headers: vec![],
                            body: Some(truncate_body(&body)),
                            status: Some(status),
                        }),
                        detail: format!("Payload reflected in response (status {status}, baseline {baseline_status})"),
                    },
                    "Sanitize user input before rendering. Use framework auto-escaping.".into(),
                ));
                break;
            }

            if *attack_type == "template_injection" && payload.contains("7*7") && body.contains("49") {
                if baseline_body.contains("49") {
                    continue;
                }
                findings.push(make_finding(
                    vcvd,
                    FindingSeverity::High,
                    format!("Potential template injection on {path_part}"),
                    format!("Template expression evaluated when fuzzing {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(HttpRecord {
                            method: "GET".into(),
                            url: url.clone(),
                            headers: vec![],
                            body: Some(truncate_body(&body)),
                            status: Some(status),
                        }),
                        detail: format!("Evaluated result '49' found in response (status {status}, baseline {baseline_status})"),
                    },
                    "Use parameterized queries and strict input validation.".into(),
                ));
                break;
            }

            let baseline_has_sig = sig_regexes.iter().any(|(re, kind)| *kind == *attack_type && re.is_match(&baseline_body));
            let matched_sig = sig_regexes.iter().find(|(re, kind)| *kind == *attack_type && re.is_match(&body));

            if matched_sig.is_some() && !baseline_has_sig {
                let status_differs = status != baseline_status;
                if !status_differs && body == baseline_body {
                    continue;
                }
                let severity = if *attack_type == "sql_injection" {
                    FindingSeverity::Critical
                } else {
                    FindingSeverity::High
                };
                findings.push(make_finding(
                    vcvd,
                    severity,
                    format!("Potential {} on {path_part}", attack_type.replace('_', " ")),
                    format!("Error signature detected when fuzzing {url}"),
                    Evidence {
                        request: Some(request_record("GET", &url, &[])),
                        response: Some(HttpRecord {
                            method: "GET".into(),
                            url: url.clone(),
                            headers: vec![],
                            body: Some(truncate_body(&body)),
                            status: Some(status),
                        }),
                        detail: format!("Error response triggered (status {status}, baseline {baseline_status})"),
                    },
                    "Use parameterized queries and strict input validation.".into(),
                ));
                break;
            }
        }
    }
    findings
}

pub async fn check_server_version(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let resp = match safe_get(client, target, safety).await {
        Some(r) => r,
        None => return vec![],
    };

    let req_rec = request_record("GET", target, &[]);
    let resp_rec = capture_response(&resp, "GET", target);
    let mut findings = Vec::new();

    let server_re = regex::Regex::new(r"(?i)(nginx|apache|gunicorn|iis|tomcat|jetty|caddy|lighttpd)/[\d.]+").unwrap();

    if let Some(server_val) = resp.headers().get("server").and_then(|v| v.to_str().ok()) {
        if server_re.is_match(server_val) {
            findings.push(make_finding(
                "VC-INFRA-001",
                FindingSeverity::Low,
                format!("Server version disclosure: {server_val}"),
                format!("Server header at {target} reveals version: {server_val}"),
                Evidence {
                    request: Some(req_rec.clone()),
                    response: Some(resp_rec.clone()),
                    detail: format!("Server header: {server_val}"),
                },
                "Remove version information from the Server header. For nginx: server_tokens off; For Apache: ServerTokens Prod".into(),
            ));
        }
    }

    if let Some(powered) = resp.headers().get("x-powered-by").and_then(|v| v.to_str().ok()) {
        findings.push(make_finding(
            "VC-INFRA-001",
            FindingSeverity::Low,
            format!("Server version disclosure: {powered}"),
            format!("X-Powered-By header at {target} reveals technology: {powered}"),
            Evidence {
                request: Some(req_rec),
                response: Some(resp_rec),
                detail: format!("X-Powered-By header: {powered}"),
            },
            "Remove the X-Powered-By header from responses.".into(),
        ));
    }

    findings
}

pub async fn check_null_origin_cors(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    if !safety.check_scope(target) {
        return vec![];
    }
    safety.acquire_rate_limit().await;
    safety.log_action("http_request", target, "CORS probe with null origin");

    let resp = match client.get(target)
        .header("Origin", "null")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let acao = resp.headers().get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let allows_creds = resp.headers().get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("") == "true";

    if acao != "null" {
        return vec![];
    }

    let (severity, title) = if allows_creds {
        (FindingSeverity::Critical, "CORS allows null origin with credentials")
    } else {
        (FindingSeverity::High, "CORS allows null origin")
    };

    vec![make_finding(
        "VC-INFRA-002",
        severity,
        title.into(),
        format!("CORS at {target} reflects null origin (credentials={allows_creds})"),
        Evidence {
            request: Some(request_record("GET", target, &[("Origin".into(), "null".into())])),
            response: Some(capture_response(&resp, "GET", target)),
            detail: format!("Access-Control-Allow-Origin: null, credentials: {allows_creds}"),
        },
        "Never reflect the null origin. Explicitly list allowed origins.".into(),
    )]
}

pub async fn check_api_exposure(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let paths = [
        "/api", "/api/", "/api/v1", "/api/users", "/api/products",
        "/api/orders", "/api/settings", "/api/config", "/api/admin",
        "/api/auth", "/api/me", "/api/profile", "/graphql", "/rest",
    ];

    let sensitive_re = regex::Regex::new(r#"(?i)"(password|email|token|secret|key)"\s*:"#).unwrap();
    let mut findings = Vec::new();

    for path in &paths {
        let url = format!("{base}{path}");
        let resp = match safe_get(client, &url, safety).await {
            Some(r) => r,
            None => continue,
        };

        if resp.status().as_u16() != 200 {
            continue;
        }

        let content_type = resp.headers().get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !content_type.contains("json") {
            continue;
        }

        let resp_rec = capture_response(&resp, "GET", &url);
        let body = resp.text().await.unwrap_or_default();
        let has_sensitive = sensitive_re.is_match(&body);

        let (severity, vcvd, title) = if has_sensitive {
            (FindingSeverity::Critical, "VC-DATA-001", format!("API exposes sensitive data without auth: {path}"))
        } else {
            (FindingSeverity::High, "VC-API-001", format!("Unauthenticated API endpoint: {path}"))
        };

        let body_snippet = if body.len() > 500 { &body[..500] } else { &body };

        let mut rr = resp_rec;
        rr.body = Some(truncate_body(&body));

        findings.push(make_finding(
            vcvd,
            severity,
            title,
            format!("API endpoint {url} returns JSON without authentication"),
            Evidence {
                request: Some(request_record("GET", &url, &[])),
                response: Some(rr),
                detail: format!("Response (first 500 chars): {body_snippet}"),
            },
            "Protect API endpoints with authentication middleware. Never expose data endpoints without auth.".into(),
        ));
    }
    findings
}

pub async fn check_permissions_policy(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let resp = match safe_get(client, target, safety).await {
        Some(r) => r,
        None => return vec![],
    };

    let headers: Vec<String> = resp.headers().keys().map(|k| k.to_string().to_lowercase()).collect();
    let has_permissions = headers.iter().any(|h| h == "permissions-policy");
    let has_feature = headers.iter().any(|h| h == "feature-policy");

    if has_permissions || has_feature {
        return vec![];
    }

    vec![make_finding(
        "VC-INFRA-003",
        FindingSeverity::Low,
        "Missing Permissions-Policy header".into(),
        format!("Response from {target} is missing both Permissions-Policy and Feature-Policy headers"),
        Evidence {
            request: Some(request_record("GET", target, &[])),
            response: Some(capture_response(&resp, "GET", target)),
            detail: "Neither Permissions-Policy nor Feature-Policy header found".into(),
        },
        "Add Permissions-Policy header to restrict browser features: Permissions-Policy: camera=(), microphone=(), geolocation=()".into(),
    )]
}

pub async fn check_sequential_ids(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let paths = ["/api/users", "/api/products", "/api/orders", "/api/v1/users", "/api/v1/products"];

    let mut findings = Vec::new();
    for path in &paths {
        let url = format!("{base}{path}");
        let resp = match safe_get(client, &url, safety).await {
            Some(r) => r,
            None => continue,
        };

        if resp.status().as_u16() != 200 {
            continue;
        }

        let content_type = resp.headers().get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !content_type.contains("json") {
            continue;
        }

        let resp_rec = capture_response(&resp, "GET", &url);
        let body = resp.text().await.unwrap_or_default();

        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body);
        let arr = match parsed {
            Ok(serde_json::Value::Array(ref items)) => items,
            _ => continue,
        };

        let ids: Vec<i64> = arr.iter()
            .filter_map(|item| item.get("id").and_then(|v| v.as_i64()))
            .collect();

        if ids.len() < 3 {
            continue;
        }

        let mut sequential_count = 0usize;
        for w in ids.windows(2) {
            if (w[1] - w[0]).abs() == 1 {
                sequential_count += 1;
            }
        }

        if sequential_count < ids.len() - 1 {
            continue;
        }

        let mut rr = resp_rec;
        rr.body = Some(truncate_body(&body));

        findings.push(make_finding(
            "VC-DATA-001",
            FindingSeverity::Medium,
            format!("Sequential IDs in API response: {path}"),
            format!("Endpoint {url} returns objects with sequential integer IDs without auth"),
            Evidence {
                request: Some(request_record("GET", &url, &[])),
                response: Some(rr),
                detail: format!("Found {} sequential IDs: {:?}", ids.len(), &ids[..ids.len().min(10)]),
            },
            "Use UUIDs instead of sequential integers for resource IDs, or ensure ownership checks on every request.".into(),
        ));
    }
    findings
}

pub async fn check_robots_sitemap(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let mut findings = Vec::new();

    let robots_url = format!("{base}/robots.txt");
    let sitemap_url = format!("{base}/sitemap.xml");

    let robots_resp = safe_get(client, &robots_url, safety).await;
    let sitemap_resp = safe_get(client, &sitemap_url, safety).await;

    let robots_ok = robots_resp.as_ref().map(|r| r.status().as_u16() == 200).unwrap_or(false);
    let sitemap_ok = sitemap_resp.as_ref().map(|r| r.status().as_u16() == 200).unwrap_or(false);

    if robots_ok {
        let resp = robots_resp.unwrap();
        let resp_rec = capture_response(&resp, "GET", &robots_url);
        let body = resp.text().await.unwrap_or_default();

        let disallow_re = regex::Regex::new(r"(?i)^Disallow:\s*(.+)$").unwrap();
        let disallowed: Vec<String> = body.lines()
            .filter_map(|line| disallow_re.captures(line))
            .filter_map(|caps| caps.get(1).map(|m| m.as_str().trim().to_string()))
            .filter(|p| !p.is_empty() && p != "/")
            .collect();

        if !disallowed.is_empty() {
            let paths_str = disallowed.join(", ");
            let mut rr = resp_rec;
            rr.body = Some(truncate_body(&body));
            findings.push(make_finding(
                "VC-INFRA-003",
                FindingSeverity::Low,
                format!("robots.txt reveals paths: {paths_str}"),
                format!("robots.txt at {robots_url} discloses potentially sensitive paths"),
                Evidence {
                    request: Some(request_record("GET", &robots_url, &[])),
                    response: Some(rr),
                    detail: format!("Disallowed paths: {paths_str}"),
                },
                "Review robots.txt entries — hidden paths may still be accessible to attackers.".into(),
            ));
        }
    }

    if !robots_ok && !sitemap_ok {
        findings.push(make_finding(
            "VC-INFRA-003",
            FindingSeverity::Low,
            "Missing robots.txt".into(),
            format!("Neither robots.txt nor sitemap.xml found at {base}"),
            Evidence {
                request: Some(request_record("GET", &robots_url, &[])),
                response: None,
                detail: "Both /robots.txt and /sitemap.xml returned non-200 or failed".into(),
            },
            "Add a robots.txt to control crawler behavior and a sitemap.xml for SEO.".into(),
        ));
    }

    findings
}

pub async fn check_technology_stack(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let resp = match safe_get(client, target, safety).await {
        Some(r) => r,
        None => return vec![],
    };

    let req_rec = request_record("GET", target, &[]);
    let mut techs: Vec<String> = Vec::new();
    let mut vuln_findings: Vec<Finding> = Vec::new();

    // Header-based detection
    if let Some(server) = resp.headers().get("server").and_then(|v| v.to_str().ok()) {
        techs.push(format!("Server: {server}"));
    }
    if let Some(powered) = resp.headers().get("x-powered-by").and_then(|v| v.to_str().ok()) {
        techs.push(format!("Framework: {powered}"));
    }
    if let Some(gen) = resp.headers().get("x-generator").and_then(|v| v.to_str().ok()) {
        techs.push(format!("CMS: {gen}"));
    }
    if resp.headers().get("x-drupal-cache").is_some() || resp.headers().get("x-drupal-dynamic-cache").is_some() {
        techs.push("CMS: Drupal".into());
    }
    if resp.headers().get("x-wordpress").is_some() {
        techs.push("CMS: WordPress".into());
    }
    if let Some(aspnet) = resp.headers().get("x-aspnet-version").and_then(|v| v.to_str().ok()) {
        techs.push(format!("Framework: ASP.NET {aspnet}"));
    }
    if let Some(mvc) = resp.headers().get("x-aspnetmvc-version").and_then(|v| v.to_str().ok()) {
        techs.push(format!("Framework: ASP.NET MVC {mvc}"));
    }

    let cookie_header = resp.headers().get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    if cookie_header.contains("wp-") {
        techs.push("CMS: WordPress (cookie)".into());
    }

    let resp_rec = capture_response(&resp, "GET", target);
    let body = resp.text().await.unwrap_or_default();

    // Body-based detection
    let body_patterns: &[(&str, &str)] = &[
        ("wp-content/", "CMS: WordPress"),
        ("wp-includes/", "CMS: WordPress"),
        ("sites/default/files/", "CMS: Drupal"),
        ("/media/jui/", "CMS: Joomla"),
        ("_next/static/", "Framework: Next.js"),
        ("__nuxt", "Framework: Nuxt.js"),
        ("data-reactroot", "Framework: React"),
        ("__NEXT_DATA__", "Framework: Next.js"),
        ("vendor/laravel", "Framework: Laravel"),
        ("csrfmiddlewaretoken", "Framework: Django"),
        ("_rails", "Framework: Rails"),
    ];

    for (pattern, tech) in body_patterns {
        if body.contains(pattern) && !techs.iter().any(|t| t == *tech) {
            techs.push(tech.to_string());
        }
    }

    let ng_re = regex::Regex::new(r#"ng-version="([^"]+)""#).unwrap();
    if let Some(caps) = ng_re.captures(&body) {
        let ver = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
        techs.push(format!("Framework: Angular {ver}"));
    }

    if body.contains("vite") {
        let vite_re = regex::Regex::new(r#"<script[^>]*src="[^"]*vite[^"]*""#).unwrap();
        if vite_re.is_match(&body) {
            techs.push("Build: Vite".into());
        }
    }

    if body.contains("svelte") {
        techs.push("Framework: Svelte/SvelteKit".into());
    }

    // jQuery version detection + vulnerability check
    let jquery_re = regex::Regex::new(r"jquery[/-](\d+\.\d+\.\d+)").unwrap();
    if let Some(caps) = jquery_re.captures(&body) {
        let ver = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
        if is_version_lt(ver, "3.5.0") {
            techs.push(format!("JS Libraries: jQuery {ver} (VULNERABLE - CVE-2020-11022)"));
            vuln_findings.push(make_finding(
                "VC-FE-001",
                FindingSeverity::High,
                format!("Vulnerable JavaScript library: jQuery {ver}"),
                format!("jQuery {ver} < 3.5.0 is vulnerable to XSS (CVE-2020-11022)"),
                Evidence {
                    request: Some(req_rec.clone()),
                    response: Some(resp_rec.clone()),
                    detail: format!("Detected jQuery {ver} in page source"),
                },
                "Upgrade jQuery to >= 3.5.0".into(),
            ));
        } else {
            techs.push(format!("JS Libraries: jQuery {ver}"));
        }
    }

    // Bootstrap version detection
    let bootstrap_re = regex::Regex::new(r"bootstrap[./-](\d+\.\d+)").unwrap();
    if let Some(caps) = bootstrap_re.captures(&body) {
        let ver = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
        if is_version_lt(ver, "4.3.1") {
            techs.push(format!("CSS: Bootstrap {ver} (VULNERABLE - XSS in tooltip)"));
            vuln_findings.push(make_finding(
                "VC-FE-001",
                FindingSeverity::High,
                format!("Vulnerable JavaScript library: Bootstrap {ver}"),
                format!("Bootstrap {ver} < 4.3.1 is vulnerable to XSS in tooltip/popover"),
                Evidence {
                    request: Some(req_rec.clone()),
                    response: Some(resp_rec.clone()),
                    detail: format!("Detected Bootstrap {ver} in page source"),
                },
                "Upgrade Bootstrap to >= 4.3.1".into(),
            ));
        } else {
            techs.push(format!("CSS: Bootstrap {ver}"));
        }
    }

    // Angular.js version detection
    let angularjs_re = regex::Regex::new(r"angular[./-](\d+\.\d+\.\d+)").unwrap();
    if let Some(caps) = angularjs_re.captures(&body) {
        let ver = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
        if ver.starts_with("1.") && is_version_lt(ver, "1.8.0") {
            techs.push(format!("JS Libraries: AngularJS {ver} (VULNERABLE - Multiple XSS)"));
            vuln_findings.push(make_finding(
                "VC-FE-001",
                FindingSeverity::High,
                format!("Vulnerable JavaScript library: AngularJS {ver}"),
                format!("AngularJS {ver} < 1.8.0 has multiple XSS vulnerabilities"),
                Evidence {
                    request: Some(req_rec.clone()),
                    response: Some(resp_rec.clone()),
                    detail: format!("Detected AngularJS {ver} in page source"),
                },
                "Upgrade AngularJS to >= 1.8.0 or migrate to modern Angular".into(),
            ));
        }
    }

    // Lodash version detection
    let lodash_re = regex::Regex::new(r"lodash[./-](\d+\.\d+\.\d+)").unwrap();
    if let Some(caps) = lodash_re.captures(&body) {
        let ver = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
        if is_version_lt(ver, "4.17.21") {
            techs.push(format!("JS Libraries: Lodash {ver} (VULNERABLE - Prototype pollution)"));
            vuln_findings.push(make_finding(
                "VC-FE-001",
                FindingSeverity::High,
                format!("Vulnerable JavaScript library: Lodash {ver}"),
                format!("Lodash {ver} < 4.17.21 is vulnerable to prototype pollution"),
                Evidence {
                    request: Some(req_rec.clone()),
                    response: Some(resp_rec.clone()),
                    detail: format!("Detected Lodash {ver} in page source"),
                },
                "Upgrade Lodash to >= 4.17.21".into(),
            ));
        }
    }

    // Moment.js detection
    let moment_re = regex::Regex::new(r"moment[./-](\d+\.\d+\.\d+)").unwrap();
    if let Some(caps) = moment_re.captures(&body) {
        let ver = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
        techs.push(format!("JS Libraries: Moment.js {ver} (VULNERABLE - unmaintained, ReDoS)"));
        vuln_findings.push(make_finding(
            "VC-FE-001",
            FindingSeverity::High,
            format!("Vulnerable JavaScript library: Moment.js {ver}"),
            format!("Moment.js {ver} is unmaintained and susceptible to ReDoS"),
            Evidence {
                request: Some(req_rec.clone()),
                response: Some(resp_rec.clone()),
                detail: format!("Detected Moment.js {ver} in page source"),
            },
            "Replace Moment.js with date-fns, Luxon, or Day.js".into(),
        ));
    } else if body.contains("moment.min.js") || body.contains("moment.js") {
        techs.push("JS Libraries: Moment.js (VULNERABLE - unmaintained, ReDoS)".into());
        vuln_findings.push(make_finding(
            "VC-FE-001",
            FindingSeverity::High,
            "Vulnerable JavaScript library: Moment.js".into(),
            "Moment.js is unmaintained and susceptible to ReDoS".into(),
            Evidence {
                request: Some(req_rec.clone()),
                response: Some(resp_rec.clone()),
                detail: "Detected Moment.js reference in page source".into(),
            },
            "Replace Moment.js with date-fns, Luxon, or Day.js".into(),
        ));
    }

    if techs.is_empty() {
        return vuln_findings;
    }

    let summary = techs.iter()
        .map(|t| format!("- {t}"))
        .collect::<Vec<_>>()
        .join("\n");
    let description = format!("Technology stack detected:\n{summary}");

    let mut rr = resp_rec;
    rr.body = Some(truncate_body(&body));

    let mut findings = vec![make_finding(
        "VC-INFRA-001",
        FindingSeverity::Low,
        format!("Technology detected: {}", techs.first().map(|s| s.as_str()).unwrap_or("unknown")),
        description,
        Evidence {
            request: Some(req_rec),
            response: Some(rr),
            detail: format!("{} technologies identified", techs.len()),
        },
        "Remove version information from headers and page source. Keep libraries up to date.".into(),
    )];
    findings.extend(vuln_findings);
    findings
}

fn is_version_lt(version: &str, threshold: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> {
        s.split('.').filter_map(|p| p.parse().ok()).collect()
    };
    let v = parse(version);
    let t = parse(threshold);
    for i in 0..v.len().max(t.len()) {
        let a = v.get(i).copied().unwrap_or(0);
        let b = t.get(i).copied().unwrap_or(0);
        if a < b { return true; }
        if a > b { return false; }
    }
    false
}

pub async fn check_form_security(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let form_pages = [
        base.to_string(),
        format!("{base}/login"),
        format!("{base}/signup"),
        format!("{base}/register"),
        format!("{base}/contact"),
        format!("{base}/search"),
    ];

    let form_re = regex::Regex::new(r"(?is)<form[^>]*>([\s\S]*?)</form>").unwrap();
    let method_re = regex::Regex::new(r#"(?i)method\s*=\s*["']?post"#).unwrap();
    let action_re = regex::Regex::new(r#"(?i)action\s*=\s*["']([^"']*)["']"#).unwrap();
    let csrf_re = regex::Regex::new(
        r#"(?i)<input[^>]+type\s*=\s*["']hidden["'][^>]+name\s*=\s*["'](csrf|_csrf|csrfmiddlewaretoken|_token|authenticity_token|__RequestVerificationToken)["']"#
    ).unwrap();
    let csrf_re2 = regex::Regex::new(
        r#"(?i)<input[^>]+name\s*=\s*["'](csrf|_csrf|csrfmiddlewaretoken|_token|authenticity_token|__RequestVerificationToken)["'][^>]+type\s*=\s*["']hidden["']"#
    ).unwrap();
    let password_re = regex::Regex::new(r#"(?i)<input[^>]+type\s*=\s*["']password["'][^>]*>"#).unwrap();
    let autocomplete_off_re = regex::Regex::new(r#"(?i)autocomplete\s*=\s*["'](off|new-password)["']"#).unwrap();
    let has_action_re = regex::Regex::new(r#"(?i)action\s*="#).unwrap();

    let mut findings = Vec::new();
    for page_url in &form_pages {
        let (_status, _ct, body) = match safe_get_with_body(client, page_url, safety).await {
            Some(t) => t,
            None => continue,
        };

        for form_cap in form_re.captures_iter(&body) {
            let full_form = form_cap.get(0).map(|m| m.as_str()).unwrap_or("");
            let form_inner = form_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let is_post = method_re.is_match(full_form);

            if is_post && !csrf_re.is_match(full_form) && !csrf_re2.is_match(full_form) {
                findings.push(make_finding(
                    "VC-FE-004",
                    FindingSeverity::High,
                    "Missing CSRF token in POST form".into(),
                    format!("POST form on {page_url} lacks a CSRF token hidden input"),
                    Evidence {
                        request: Some(request_record("GET", page_url, &[])),
                        response: None,
                        detail: format!("Form snippet: {}", &full_form[..full_form.len().min(300)]),
                    },
                    "Add a CSRF token hidden field to every POST form.".into(),
                ));
            }

            if let Some(action_cap) = action_re.captures(full_form) {
                let action_val = action_cap.get(1).map(|m| m.as_str()).unwrap_or("");
                if action_val.starts_with("http://") {
                    findings.push(make_finding(
                        "VC-INFRA-006",
                        FindingSeverity::Medium,
                        "Form action over HTTP".into(),
                        format!("Form on {page_url} submits to insecure URL: {action_val}"),
                        Evidence {
                            request: Some(request_record("GET", page_url, &[])),
                            response: None,
                            detail: format!("Form action: {action_val}"),
                        },
                        "Change form action to use HTTPS.".into(),
                    ));
                }
            }

            for pw_match in password_re.find_iter(form_inner) {
                let pw_tag = pw_match.as_str();
                if !autocomplete_off_re.is_match(pw_tag) {
                    findings.push(make_finding(
                        "VC-FE-008",
                        FindingSeverity::Low,
                        "Password field without autocomplete=off".into(),
                        format!("Password input on {page_url} does not set autocomplete=\"off\" or \"new-password\""),
                        Evidence {
                            request: Some(request_record("GET", page_url, &[])),
                            response: None,
                            detail: format!("Input tag: {}", &pw_tag[..pw_tag.len().min(200)]),
                        },
                        "Add autocomplete=\"off\" or autocomplete=\"new-password\" to password fields.".into(),
                    ));
                    break;
                }
            }

            if is_post && !has_action_re.is_match(full_form) {
                findings.push(make_finding(
                    "VC-FE-004",
                    FindingSeverity::Low,
                    "POST form missing action attribute".into(),
                    format!("POST form on {page_url} has no action attribute; may rely on JS handling"),
                    Evidence {
                        request: Some(request_record("GET", page_url, &[])),
                        response: None,
                        detail: format!("Form snippet: {}", &full_form[..full_form.len().min(300)]),
                    },
                    "Consider adding an explicit action attribute or ensure JS fallback works with CSP.".into(),
                ));
            }
        }
    }
    findings
}

pub async fn check_open_redirect(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let test_urls = [
        format!("{base}?redirect=https://evil.com"),
        format!("{base}?next=https://evil.com"),
        format!("{base}?url=https://evil.com"),
        format!("{base}?return=https://evil.com"),
        format!("{base}?returnTo=https://evil.com"),
        format!("{base}?continue=https://evil.com"),
        format!("{base}/login?redirect=https://evil.com"),
        format!("{base}/auth/callback?redirect_uri=https://evil.com"),
    ];

    let meta_refresh_re = regex::Regex::new(r#"(?i)<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]*evil\.com"#).unwrap();
    let window_loc_re = regex::Regex::new(r"(?i)window\.location[^;]*evil\.com").unwrap();

    let mut findings = Vec::new();
    for url in &test_urls {
        if !safety.check_scope(url) {
            continue;
        }
        safety.acquire_rate_limit().await;
        safety.log_action("http_request", url, "Open redirect probe");

        let resp = match client.get(url.as_str()).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = resp.status().as_u16();
        let location = resp.headers().get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let resp_rec = capture_response(&resp, "GET", url);
        let body = resp.text().await.unwrap_or_default();

        let redirect_confirmed = (300..400).contains(&status) && location.contains("evil.com");
        let meta_redirect = meta_refresh_re.is_match(&body);
        let js_redirect = window_loc_re.is_match(&body);

        if !redirect_confirmed && !meta_redirect && !js_redirect {
            continue;
        }

        let detail = if redirect_confirmed {
            format!("3xx redirect to Location: {location}")
        } else if meta_redirect {
            "meta http-equiv=refresh redirects to evil.com".into()
        } else {
            "window.location redirects to evil.com".into()
        };

        let mut rr = resp_rec;
        rr.body = Some(truncate_body(&body));

        findings.push(make_finding(
            "VC-FE-005",
            FindingSeverity::High,
            format!("Open redirect: {url}"),
            format!("Server redirects to attacker-controlled URL via {url}"),
            Evidence {
                request: Some(request_record("GET", url, &[])),
                response: Some(rr),
                detail,
            },
            "Validate redirect targets against an allowlist. Never use user input directly in redirect URLs.".into(),
        ));
    }
    findings
}

pub async fn check_error_pages(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let mut findings = Vec::new();

    let version_re = regex::Regex::new(r"(?i)(nginx|apache|iis|tomcat|express|django|laravel|flask|gunicorn|jetty|caddy|lighttpd|kestrel)/[\d.]+").unwrap();
    let stack_re = regex::Regex::new(r"(?i)(stack\s*trace|traceback|at\s+\w+\.\w+\s*\(|\.java:\d+|\.py:\d+|\.js:\d+|\.cs:\d+)").unwrap();
    let framework_re = regex::Regex::new(r"(?i)(laravel|symfony|whoops|debug\s*mode|django\s*debug|express\s*error|next\.js\s*error|rails\s*error)").unwrap();
    let filepath_re = regex::Regex::new(r"(?:(/[a-z_][a-z0-9_/.-]+\.(py|js|rb|java|php|cs))|([A-Z]:\\[^\s<]+\.(py|js|rb|java|php|cs)))").unwrap();
    let internal_ip_re = regex::Regex::new(r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})").unwrap();

    let long_path = "a".repeat(8100);
    let probes: Vec<(String, &str)> = vec![
        (format!("{base}/firebreak-test-404-nonexistent"), "404 page"),
        (format!("{base}/{long_path}"), "long URL"),
    ];

    for (url, label) in &probes {
        let (status, _ct, body) = match safe_get_with_body(client, url, safety).await {
            Some(t) => t,
            None => continue,
        };

        let status_code = status.as_u16();
        let checks: Vec<(&regex::Regex, &str)> = vec![
            (&version_re, "server version in error page"),
            (&stack_re, "stack trace in error page"),
            (&framework_re, "framework default error page"),
            (&filepath_re, "file paths in error page"),
            (&internal_ip_re, "internal IP address in error page"),
        ];

        for (re, detail) in &checks {
            let matched = re.find(&body);
            if matched.is_none() {
                continue;
            }
            let snippet = matched.unwrap().as_str();
            findings.push(make_finding(
                "VC-INFRA-001",
                FindingSeverity::Medium,
                format!("Error page information disclosure: {detail}"),
                format!("Error response from {label} at {url} leaks {detail}"),
                Evidence {
                    request: Some(request_record("GET", url, &[])),
                    response: Some(HttpRecord {
                        method: "GET".into(),
                        url: url.clone(),
                        headers: vec![],
                        body: Some(truncate_body(&body)),
                        status: Some(status_code),
                    }),
                    detail: format!("Matched: {}", &snippet[..snippet.len().min(200)]),
                },
                "Configure custom error pages that do not reveal server internals.".into(),
            ));
        }
    }

    let propfind_url = format!("{base}/");
    if safety.check_scope(&propfind_url) {
        safety.acquire_rate_limit().await;
        safety.log_action("http_request", &propfind_url, "PROPFIND method probe");

        let method = reqwest::Method::from_bytes(b"PROPFIND").unwrap_or(reqwest::Method::OPTIONS);
        let resp = client.request(method, &propfind_url).send().await;

        if let Ok(r) = resp {
            let status_code = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();

            let checks: Vec<(&regex::Regex, &str)> = vec![
                (&version_re, "server version in error page"),
                (&stack_re, "stack trace in error page"),
                (&framework_re, "framework default error page"),
                (&filepath_re, "file paths in error page"),
                (&internal_ip_re, "internal IP address in error page"),
            ];

            for (re, detail) in &checks {
                let matched = re.find(&body);
                if matched.is_none() {
                    continue;
                }
                let snippet = matched.unwrap().as_str();
                findings.push(make_finding(
                    "VC-INFRA-001",
                    FindingSeverity::Medium,
                    format!("Error page information disclosure: {detail}"),
                    format!("PROPFIND error response at {propfind_url} leaks {detail}"),
                    Evidence {
                        request: Some(request_record("PROPFIND", &propfind_url, &[])),
                        response: Some(HttpRecord {
                            method: "PROPFIND".into(),
                            url: propfind_url.clone(),
                            headers: vec![],
                            body: Some(truncate_body(&body)),
                            status: Some(status_code),
                        }),
                        detail: format!("Matched: {}", &snippet[..snippet.len().min(200)]),
                    },
                    "Configure custom error pages that do not reveal server internals.".into(),
                ));
            }
        }
    }

    findings
}

pub async fn check_cookie_security(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let urls = [
        base.to_string(),
        format!("{base}/login"),
        format!("{base}/api"),
        format!("{base}/auth"),
        format!("{base}/account"),
    ];

    let is_https = target.starts_with("https://");
    let sensitive_names = ["session", "token", "auth", "sid", "jwt", "csrf"];
    let mut findings = Vec::new();

    for url in &urls {
        let resp = match safe_get(client, url, safety).await {
            Some(r) => r,
            None => continue,
        };

        let req_rec = request_record("GET", url, &[]);
        let resp_rec = capture_response(&resp, "GET", url);
        let set_cookie_values: Vec<String> = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok().map(String::from))
            .collect();

        for raw in &set_cookie_values {
            let parts: Vec<&str> = raw.split(';').collect();
            let name_value = parts[0].trim();
            let cookie_name = name_value.split('=').next().unwrap_or("").trim().to_lowercase();
            let lower = raw.to_lowercase();
            let is_sensitive = sensitive_names.iter().any(|s| cookie_name.contains(s));

            if is_sensitive && !lower.contains("httponly") {
                findings.push(make_finding(
                    "VC-FE-003",
                    FindingSeverity::High,
                    format!("Cookie '{cookie_name}' missing HttpOnly flag"),
                    format!("Sensitive cookie at {url} lacks HttpOnly — XSS can steal it"),
                    Evidence {
                        request: Some(req_rec.clone()),
                        response: Some(resp_rec.clone()),
                        detail: format!("Set-Cookie: {raw}"),
                    },
                    "Add HttpOnly flag to session/auth cookies.".into(),
                ));
            }

            if is_https && !lower.contains("secure") {
                findings.push(make_finding(
                    "VC-FE-003",
                    FindingSeverity::Medium,
                    format!("Cookie '{cookie_name}' missing Secure flag"),
                    format!("Cookie at {url} sent over HTTP on an HTTPS site"),
                    Evidence {
                        request: Some(req_rec.clone()),
                        response: Some(resp_rec.clone()),
                        detail: format!("Set-Cookie: {raw}"),
                    },
                    "Add Secure flag so cookie is only sent over HTTPS.".into(),
                ));
            }

            let has_samesite = lower.contains("samesite");
            let samesite_none_no_secure =
                lower.contains("samesite=none") && !lower.contains("secure");
            if !has_samesite || samesite_none_no_secure {
                let detail_msg = if samesite_none_no_secure {
                    "SameSite=None without Secure flag"
                } else {
                    "Missing SameSite attribute"
                };
                findings.push(make_finding(
                    "VC-FE-004",
                    FindingSeverity::Medium,
                    format!("Cookie '{cookie_name}' {detail_msg}"),
                    format!("Cookie at {url} vulnerable to CSRF: {detail_msg}"),
                    Evidence {
                        request: Some(req_rec.clone()),
                        response: Some(resp_rec.clone()),
                        detail: format!("Set-Cookie: {raw}"),
                    },
                    "Set SameSite=Lax or SameSite=Strict on cookies.".into(),
                ));
            }

            if is_sensitive {
                let has_broad_path = parts.iter().any(|p| {
                    let t = p.trim().to_lowercase();
                    t.starts_with("path") && t.contains('/')
                });
                if has_broad_path {
                    findings.push(make_finding(
                        "VC-FE-004",
                        FindingSeverity::Low,
                        format!("Session cookie '{cookie_name}' has broad Path=/"),
                        format!("Session cookie at {url} scoped to root path"),
                        Evidence {
                            request: Some(req_rec.clone()),
                            response: Some(resp_rec.clone()),
                            detail: format!("Set-Cookie: {raw}"),
                        },
                        "Scope session cookies to the narrowest path needed.".into(),
                    ));
                }
            }

            if is_sensitive {
                let long_expiry = parts.iter().any(|p| {
                    let trimmed = p.trim().to_lowercase();
                    if let Some(val) = trimmed.strip_prefix("max-age=") {
                        if let Ok(secs) = val.trim().parse::<u64>() {
                            return secs > 86400 * 30;
                        }
                    }
                    false
                });
                if long_expiry {
                    findings.push(make_finding(
                        "VC-AUTH-005",
                        FindingSeverity::Medium,
                        format!("Session cookie '{cookie_name}' has long expiry (>30 days)"),
                        format!("Session cookie at {url} persists too long, increasing hijack window"),
                        Evidence {
                            request: Some(req_rec.clone()),
                            response: Some(resp_rec.clone()),
                            detail: format!("Set-Cookie: {raw}"),
                        },
                        "Reduce session cookie Max-Age to 24 hours or less.".into(),
                    ));
                }
            }
        }
    }
    findings
}

pub async fn check_http_methods(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    if !safety.check_scope(target) {
        return vec![];
    }

    let mut findings = Vec::new();

    safety.acquire_rate_limit().await;
    safety.log_action("http_request", target, "OPTIONS request");
    if let Ok(resp) = client.request(reqwest::Method::OPTIONS, target).send().await {
        let resp_rec = capture_response(&resp, "OPTIONS", target);
        let allow = resp
            .headers()
            .get("allow")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_uppercase();

        if allow.contains("TRACE") {
            findings.push(make_finding(
                "VC-INFRA-003",
                FindingSeverity::Medium,
                "TRACE method allowed".into(),
                format!("Server at {target} allows TRACE — cross-site tracing risk"),
                Evidence {
                    request: Some(request_record("OPTIONS", target, &[])),
                    response: Some(resp_rec.clone()),
                    detail: format!("Allow: {allow}"),
                },
                "Disable TRACE method on the web server.".into(),
            ));
        }

        if allow.contains("PUT") || allow.contains("DELETE") {
            let methods: Vec<&str> = ["PUT", "DELETE"]
                .iter()
                .copied()
                .filter(|m| allow.contains(m))
                .collect();
            findings.push(make_finding(
                "VC-INFRA-003",
                FindingSeverity::Medium,
                format!("Unexpected write methods allowed: {}", methods.join(", ")),
                format!("Server at {target} allows {} on the main URL", methods.join("/")),
                Evidence {
                    request: Some(request_record("OPTIONS", target, &[])),
                    response: Some(resp_rec),
                    detail: format!("Allow: {allow}"),
                },
                "Restrict HTTP methods to only those required (GET, POST, HEAD).".into(),
            ));
        }
    }

    safety.acquire_rate_limit().await;
    safety.log_action("http_request", target, "TRACE request");
    let trace_method = reqwest::Method::from_bytes(b"TRACE").unwrap_or(reqwest::Method::GET);
    if let Ok(resp) = client.request(trace_method, target).send().await {
        let status = resp.status().as_u16();
        let resp_rec = capture_response(&resp, "TRACE", target);
        let body = resp.text().await.unwrap_or_default();
        if status == 200 && (body.contains("TRACE") || body.contains("trace")) {
            findings.push(make_finding(
                "VC-INFRA-003",
                FindingSeverity::High,
                "TRACE method echoes request".into(),
                format!("TRACE at {target} returned 200 with request echo — XST risk"),
                Evidence {
                    request: Some(request_record("TRACE", target, &[])),
                    response: Some(HttpRecord {
                        body: Some(truncate_body(&body)),
                        ..resp_rec
                    }),
                    detail: "TRACE request echoed back".into(),
                },
                "Disable TRACE method on the web server.".into(),
            ));
        }
    }

    safety.acquire_rate_limit().await;
    safety.log_action("http_request", target, "HEAD request");
    if let Ok(head_resp) = client.head(target).send().await {
        let head_headers: Vec<String> = head_resp
            .headers()
            .keys()
            .map(|k| k.to_string().to_lowercase())
            .collect();

        if let Some(get_resp) = safe_get(client, target, safety).await {
            let get_headers: Vec<String> = get_resp
                .headers()
                .keys()
                .map(|k| k.to_string().to_lowercase())
                .collect();

            let head_only: Vec<&String> = head_headers
                .iter()
                .filter(|h| !get_headers.contains(h))
                .collect();

            if !head_only.is_empty() {
                findings.push(make_finding(
                    "VC-INFRA-001",
                    FindingSeverity::Low,
                    "HEAD response reveals extra headers".into(),
                    format!(
                        "HEAD at {target} returns headers not present in GET: {}",
                        head_only.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    ),
                    Evidence {
                        request: Some(request_record("HEAD", target, &[])),
                        response: Some(capture_response(&head_resp, "HEAD", target)),
                        detail: format!("Extra headers in HEAD: {:?}", head_only),
                    },
                    "Ensure HEAD and GET return consistent headers.".into(),
                ));
            }
        }
    }

    findings
}

pub async fn check_mixed_content(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    if !target.starts_with("https://") {
        return vec![];
    }

    let (_, _, body) = match safe_get_with_body(client, target, safety).await {
        Some(t) => t,
        None => return vec![],
    };

    let body_lower = body.to_lowercase();
    let mut findings = Vec::new();

    let active_patterns: &[(&str, &str)] = &[
        ("<script", "src="),
        ("<link", "href="),
        ("<iframe", "src="),
    ];

    for (tag, attr) in active_patterns {
        let search_tag = *tag;
        let mut pos = 0;
        while let Some(idx) = body_lower[pos..].find(search_tag) {
            let abs_idx = pos + idx;
            let end = (abs_idx + 500).min(body_lower.len());
            let chunk = &body_lower[abs_idx..end];
            let tag_end = chunk.find('>').unwrap_or(chunk.len());
            let tag_content = &chunk[..tag_end];

            if let Some(attr_idx) = tag_content.find(attr) {
                let after_attr = &tag_content[attr_idx + attr.len()..];
                let val = after_attr.trim_start_matches(['"', '\'']);
                if val.starts_with("http://") {
                    let url_end = val
                        .find(['"', '\'', ' ', '>'])
                        .unwrap_or(val.len());
                    let mixed_url_str = &val[..url_end];

                    findings.push(make_finding(
                        "VC-INFRA-006",
                        FindingSeverity::High,
                        format!("Active mixed content: {search_tag} loads HTTP resource"),
                        format!("HTTPS page at {target} loads {search_tag} from {mixed_url_str}"),
                        Evidence {
                            request: Some(request_record("GET", target, &[])),
                            response: None,
                            detail: format!("Mixed content: {search_tag} {attr}{mixed_url_str}"),
                        },
                        "Change all resource URLs to HTTPS or use protocol-relative URLs.".into(),
                    ));
                }
            }
            pos = abs_idx + 1;
        }
    }

    let mut img_pos = 0;
    while let Some(idx) = body_lower[img_pos..].find("<img") {
        let abs_idx = img_pos + idx;
        let end = (abs_idx + 500).min(body_lower.len());
        let chunk = &body_lower[abs_idx..end];
        let tag_end = chunk.find('>').unwrap_or(chunk.len());
        let tag_content = &chunk[..tag_end];

        if let Some(attr_idx) = tag_content.find("src=") {
            let after_attr = &tag_content[attr_idx + 4..];
            let val = after_attr.trim_start_matches(['"', '\'']);
            if val.starts_with("http://") {
                let url_end = val
                    .find(['"', '\'', ' ', '>'])
                    .unwrap_or(val.len());
                let img_url = &val[..url_end];

                findings.push(make_finding(
                    "VC-INFRA-006",
                    FindingSeverity::Low,
                    "Passive mixed content: <img> loads HTTP resource".into(),
                    format!("HTTPS page at {target} loads image from http:// URL: {img_url}"),
                    Evidence {
                        request: Some(request_record("GET", target, &[])),
                        response: None,
                        detail: format!("Mixed content: <img src={img_url}>"),
                    },
                    "Change image URLs to HTTPS.".into(),
                ));
            }
        }
        img_pos = abs_idx + 1;
    }

    findings
}

pub async fn check_host_header_injection(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    if !safety.check_scope(target) {
        return vec![];
    }
    safety.acquire_rate_limit().await;
    safety.log_action("http_request", target, "Host header injection probe");

    let resp = match client
        .get(target)
        .header("Host", "evil.com")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let status = resp.status().as_u16();
    let resp_rec = capture_response(&resp, "GET", target);
    let body = resp.text().await.unwrap_or_default();

    if !body.contains("evil.com") {
        return vec![];
    }

    vec![make_finding(
        "VC-INJ-007",
        FindingSeverity::High,
        "Host header injection".into(),
        format!("Server at {target} reflects injected Host header value in response body"),
        Evidence {
            request: Some(request_record(
                "GET",
                target,
                &[("Host".into(), "evil.com".into())],
            )),
            response: Some(HttpRecord {
                body: Some(truncate_body(&body)),
                ..resp_rec
            }),
            detail: format!("'evil.com' reflected in response (status {status})"),
        },
        "Validate the Host header server-side. Use a whitelist of allowed hostnames.".into(),
    )]
}

pub async fn check_https_enforcement(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    if !target.starts_with("https://") {
        return vec![];
    }

    let mut findings = Vec::new();
    let http_url = target.replacen("https://", "http://", 1);

    if !safety.check_scope(&http_url) {
        return vec![];
    }
    safety.acquire_rate_limit().await;
    safety.log_action("http_request", &http_url, "HTTPS enforcement check");

    let resp = match client.get(&http_url).send().await {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let status = resp.status().as_u16();
    let location = resp.headers().get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if (300..400).contains(&status) && !location.is_empty() && !location.starts_with("https://") {
        findings.push(make_finding(
            "VC-INFRA-006",
            FindingSeverity::Medium,
            "Insecure redirect hop before HTTPS".into(),
            format!("HTTP request to {http_url} redirects to {location} (HTTP) before reaching HTTPS"),
            Evidence {
                request: Some(request_record("GET", &http_url, &[])),
                response: Some(HttpRecord {
                    method: "GET".into(),
                    url: http_url.clone(),
                    headers: vec![("location".into(), location.clone())],
                    body: None,
                    status: Some(status),
                }),
                detail: format!("First redirect hop is insecure: {location}"),
            },
            "Redirect directly from HTTP to the HTTPS URL in a single 301.".into(),
        ));
    }

    let hsts_resp = match safe_get(client, target, safety).await {
        Some(r) => r,
        None => return findings,
    };

    let hsts_resp_rec = capture_response(&hsts_resp, "GET", target);

    if let Some(hsts_val) = hsts_resp.headers().get("strict-transport-security").and_then(|v| v.to_str().ok()) {
        let hsts_lower = hsts_val.to_lowercase();

        let max_age_re = regex::Regex::new(r"max-age=(\d+)").unwrap();
        if let Some(caps) = max_age_re.captures(&hsts_lower) {
            if let Ok(age) = caps.get(1).unwrap().as_str().parse::<u64>() {
                if age < 15_768_000 {
                    findings.push(make_finding(
                        "VC-INFRA-006",
                        FindingSeverity::Medium,
                        format!("HSTS max-age too short ({age}s)"),
                        format!("HSTS max-age at {target} is {age}s, below recommended 6 months (15768000s)"),
                        Evidence {
                            request: Some(request_record("GET", target, &[])),
                            response: Some(hsts_resp_rec.clone()),
                            detail: format!("Strict-Transport-Security: {hsts_val}"),
                        },
                        "Set HSTS max-age to at least 15768000 (6 months), ideally 31536000 (1 year).".into(),
                    ));
                }
            }
        }

        if !hsts_lower.contains("includesubdomains") {
            findings.push(make_finding(
                "VC-INFRA-006",
                FindingSeverity::Low,
                "HSTS missing includeSubDomains".into(),
                format!("HSTS at {target} does not cover subdomains"),
                Evidence {
                    request: Some(request_record("GET", target, &[])),
                    response: Some(hsts_resp_rec.clone()),
                    detail: format!("Strict-Transport-Security: {hsts_val}"),
                },
                "Add includeSubDomains to the Strict-Transport-Security header.".into(),
            ));
        }

        if !hsts_lower.contains("preload") {
            findings.push(make_finding(
                "VC-INFRA-006",
                FindingSeverity::Low,
                "HSTS missing preload directive".into(),
                format!("HSTS at {target} is not configured for browser preload lists"),
                Evidence {
                    request: Some(request_record("GET", target, &[])),
                    response: Some(hsts_resp_rec.clone()),
                    detail: format!("Strict-Transport-Security: {hsts_val}"),
                },
                "Add preload to the HSTS header and submit to hstspreload.org.".into(),
            ));
        }
    }

    let https_resp = safe_get(client, target, safety).await;
    if let Some(r) = https_resp {
        let resp_rec = capture_response(&r, "GET", target);
        let body = r.text().await.unwrap_or_default();
        let http_host = http_url.trim_start_matches("http://").split('/').next().unwrap_or("");
        let self_http_pattern = format!("http://{http_host}");
        let link_re = regex::Regex::new(r#"(href|src|action)\s*=\s*["']([^"']+)["']"#).unwrap();
        let has_mixed = link_re.captures_iter(&body).any(|caps| {
            let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            val.starts_with(&self_http_pattern)
        });

        if has_mixed {
            findings.push(make_finding(
                "VC-INFRA-006",
                FindingSeverity::Medium,
                "Mixed scheme self-references on HTTPS page".into(),
                format!("HTTPS page at {target} contains links to its own HTTP version"),
                Evidence {
                    request: Some(request_record("GET", target, &[])),
                    response: Some(resp_rec),
                    detail: format!("Found href/src/action referencing {self_http_pattern}"),
                },
                "Replace all HTTP self-references with HTTPS or use protocol-relative URLs.".into(),
            ));
        }
    }

    let cookie_resp = safe_get(client, target, safety).await;
    if let Some(r) = cookie_resp {
        let cookie_resp_rec = capture_response(&r, "GET", target);
        let cookies: Vec<String> = r.headers().get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .collect();

        let has_secure_cookie = cookies.iter().any(|c| c.to_lowercase().contains("secure"));
        let http_redirects = (300..400).contains(&status) && location.starts_with("https://");

        if has_secure_cookie && !http_redirects && status < 400 {
            findings.push(make_finding(
                "VC-INFRA-006",
                FindingSeverity::Medium,
                "Secure cookies without HTTP-to-HTTPS redirect".into(),
                format!("Cookies at {target} have Secure flag but HTTP does not redirect to HTTPS"),
                Evidence {
                    request: Some(request_record("GET", &http_url, &[])),
                    response: Some(cookie_resp_rec),
                    detail: "Secure cookies are set but HTTP traffic is not redirected".into(),
                },
                "Configure the server to redirect all HTTP requests to HTTPS.".into(),
            ));
        }
    }

    findings
}

pub async fn check_security_txt(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let url = format!("{base}/.well-known/security.txt");

    let resp = match safe_get(client, &url, safety).await {
        Some(r) => r,
        None => return vec![],
    };

    let status = resp.status().as_u16();
    let resp_rec = capture_response(&resp, "GET", &url);

    if status != 200 {
        return vec![make_finding(
            "VC-INFRA-003",
            FindingSeverity::Low,
            "Missing security.txt".into(),
            format!("No security.txt found at {url} (RFC 9116). No vulnerability disclosure process advertised."),
            Evidence {
                request: Some(request_record("GET", &url, &[])),
                response: Some(resp_rec),
                detail: format!("GET {url} returned status {status}"),
            },
            "Create a /.well-known/security.txt per RFC 9116 with Contact, Expires, and Policy fields.".into(),
        )];
    }

    let body = resp.text().await.unwrap_or_default();
    if body.trim_start().starts_with('<') {
        return vec![make_finding(
            "VC-INFRA-003",
            FindingSeverity::Low,
            "Missing security.txt".into(),
            format!("security.txt at {url} returned HTML instead of plain text"),
            Evidence {
                request: Some(request_record("GET", &url, &[])),
                response: Some(resp_rec),
                detail: "Response appears to be HTML, not a valid security.txt".into(),
            },
            "Create a /.well-known/security.txt per RFC 9116 with Contact, Expires, and Policy fields.".into(),
        )];
    }

    let mut contact = String::new();
    let mut expires = String::new();
    let mut policy = String::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("Contact:") {
            contact = val.trim().to_string();
        } else if let Some(val) = trimmed.strip_prefix("Expires:") {
            expires = val.trim().to_string();
        } else if let Some(val) = trimmed.strip_prefix("Policy:") {
            policy = val.trim().to_string();
        }
    }

    let mut detail_parts = vec!["security.txt found and appears valid".to_string()];
    if !contact.is_empty() {
        detail_parts.push(format!("Contact: {contact}"));
    }
    if !expires.is_empty() {
        detail_parts.push(format!("Expires: {expires}"));
    }
    if !policy.is_empty() {
        detail_parts.push(format!("Policy: {policy}"));
    }

    vec![make_finding(
        "VC-INFRA-003",
        FindingSeverity::Low,
        "security.txt present (good practice)".into(),
        format!("security.txt found at {url} per RFC 9116"),
        Evidence {
            request: Some(request_record("GET", &url, &[])),
            response: Some(HttpRecord {
                method: "GET".into(),
                url: url.clone(),
                headers: vec![],
                body: Some(truncate_body(&body)),
                status: Some(200),
            }),
            detail: detail_parts.join("; "),
        },
        "Keep security.txt up to date. Ensure Expires field is not in the past.".into(),
    )]
}

pub async fn check_csp_quality(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let resp = match safe_get(client, target, safety).await {
        Some(r) => r,
        None => return vec![],
    };

    let csp_val = match resp.headers().get("content-security-policy").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return vec![],
    };

    let req_rec = request_record("GET", target, &[]);
    let resp_rec = capture_response(&resp, "GET", target);
    let header_names: Vec<String> = resp.headers().keys().map(|k| k.to_string().to_lowercase()).collect();
    let mut findings = Vec::new();

    let directives: Vec<(&str, &str)> = csp_val.split(';').filter_map(|part| {
        let trimmed = part.trim();
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let name = parts.next()?;
        let value = parts.next().unwrap_or("");
        Some((name, value))
    }).collect();

    let script_src = directives.iter()
        .find(|(n, _)| *n == "script-src")
        .map(|(_, v)| *v)
        .unwrap_or("");

    if script_src.contains("'unsafe-inline'") {
        findings.push(make_finding(
            "VC-INFRA-003",
            FindingSeverity::High,
            "Weak CSP: unsafe-inline in script-src".into(),
            format!("CSP at {target} allows 'unsafe-inline' in script-src, defeating XSS protection"),
            Evidence {
                request: Some(req_rec.clone()),
                response: Some(resp_rec.clone()),
                detail: format!("Content-Security-Policy: {csp_val}"),
            },
            "Remove 'unsafe-inline' from script-src. Use nonces or hashes instead.".into(),
        ));
    }

    if script_src.contains("'unsafe-eval'") {
        findings.push(make_finding(
            "VC-INFRA-003",
            FindingSeverity::Medium,
            "Weak CSP: unsafe-eval in script-src".into(),
            format!("CSP at {target} allows 'unsafe-eval' in script-src, enabling eval()"),
            Evidence {
                request: Some(req_rec.clone()),
                response: Some(resp_rec.clone()),
                detail: format!("Content-Security-Policy: {csp_val}"),
            },
            "Remove 'unsafe-eval' from script-src. Refactor code to avoid eval().".into(),
        ));
    }

    let has_wildcard = directives.iter().any(|(_, value)| {
        value.split_whitespace().any(|t| t == "*")
    });
    if has_wildcard {
        let directive_name = directives.iter()
            .find(|(_, value)| value.split_whitespace().any(|t| t == "*"))
            .map(|(n, _)| *n)
            .unwrap_or("unknown");
        findings.push(make_finding(
            "VC-INFRA-003",
            FindingSeverity::Medium,
            format!("Weak CSP: wildcard in {directive_name}"),
            format!("CSP directive {directive_name} at {target} uses wildcard '*', allowing any source"),
            Evidence {
                request: Some(req_rec.clone()),
                response: Some(resp_rec.clone()),
                detail: format!("Content-Security-Policy: {csp_val}"),
            },
            format!("Replace '*' in {directive_name} with specific allowed origins."),
        ));
    }

    let has_http_scheme = directives.iter().any(|(_, v)| v.split_whitespace().any(|t| t == "http:"));
    if has_http_scheme {
        findings.push(make_finding(
            "VC-INFRA-003",
            FindingSeverity::Medium,
            "Weak CSP: http: scheme allowed".into(),
            format!("CSP at {target} permits http: scheme, allowing mixed content"),
            Evidence {
                request: Some(req_rec.clone()),
                response: Some(resp_rec.clone()),
                detail: format!("Content-Security-Policy: {csp_val}"),
            },
            "Replace http: with https: in CSP directives.".into(),
        ));
    }

    if script_src.contains("data:") {
        findings.push(make_finding(
            "VC-INFRA-003",
            FindingSeverity::Medium,
            "Weak CSP: data: in script-src".into(),
            format!("CSP at {target} allows data: URIs in script-src, enabling inline script injection"),
            Evidence {
                request: Some(req_rec.clone()),
                response: Some(resp_rec.clone()),
                detail: format!("Content-Security-Policy: {csp_val}"),
            },
            "Remove data: from script-src.".into(),
        ));
    }

    let has_default_src = directives.iter().any(|(n, _)| *n == "default-src");
    if !has_default_src {
        findings.push(make_finding(
            "VC-INFRA-003",
            FindingSeverity::Medium,
            "Weak CSP: missing default-src".into(),
            format!("CSP at {target} has no default-src fallback directive"),
            Evidence {
                request: Some(req_rec.clone()),
                response: Some(resp_rec.clone()),
                detail: format!("Content-Security-Policy: {csp_val}"),
            },
            "Add default-src 'self' as a baseline fallback.".into(),
        ));
    }

    let has_frame_ancestors = directives.iter().any(|(n, _)| *n == "frame-ancestors");
    if !has_frame_ancestors {
        let has_xfo = header_names.iter().any(|h| h == "x-frame-options");
        if !has_xfo {
            findings.push(make_finding(
                "VC-INFRA-003",
                FindingSeverity::Low,
                "Weak CSP: missing frame-ancestors".into(),
                format!("CSP at {target} has no frame-ancestors and no X-Frame-Options, clickjacking possible"),
                Evidence {
                    request: Some(req_rec.clone()),
                    response: Some(resp_rec.clone()),
                    detail: format!("Content-Security-Policy: {csp_val}"),
                },
                "Add frame-ancestors 'self' to the CSP or set X-Frame-Options: DENY.".into(),
            ));
        }
    }

    findings
}

pub async fn check_cache_headers(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let sensitive_paths = ["/login", "/account", "/profile", "/dashboard", "/admin", "/settings"];
    let mut findings = Vec::new();

    for path in &sensitive_paths {
        let url = format!("{base}{path}");
        let resp = match safe_get(client, &url, safety).await {
            Some(r) => r,
            None => continue,
        };

        if resp.status().as_u16() != 200 {
            continue;
        }

        let req_rec = request_record("GET", &url, &[]);
        let resp_rec = capture_response(&resp, "GET", &url);

        let cache_control = resp.headers().get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        let has_pragma = resp.headers().get("pragma")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase()
            .contains("no-cache");

        let has_etag = resp.headers().get("etag").is_some();

        let body = resp.text().await.unwrap_or_default();
        let has_form = body.to_lowercase().contains("<form");

        if !cache_control.contains("no-store") && !cache_control.contains("no-cache") {
            findings.push(make_finding(
                "VC-INFRA-003",
                FindingSeverity::Medium,
                format!("Missing cache-control on sensitive page {path}"),
                format!("Sensitive page {url} lacks Cache-Control: no-store/no-cache, browser may cache credentials"),
                Evidence {
                    request: Some(req_rec.clone()),
                    response: Some(resp_rec.clone()),
                    detail: format!("Cache-Control: {cache_control}"),
                },
                format!("Add Cache-Control: no-store, no-cache, must-revalidate to {path}."),
            ));
        }

        if cache_control.contains("public") && has_form {
            findings.push(make_finding(
                "VC-INFRA-003",
                FindingSeverity::Medium,
                format!("Public cache on page with forms: {path}"),
                format!("Sensitive page {url} has Cache-Control: public and contains forms"),
                Evidence {
                    request: Some(req_rec.clone()),
                    response: Some(resp_rec.clone()),
                    detail: format!("Cache-Control: {cache_control}, page contains <form>"),
                },
                format!("Change Cache-Control to private or no-store on {path}."),
            ));
        }

        if !has_pragma {
            findings.push(make_finding(
                "VC-INFRA-003",
                FindingSeverity::Low,
                format!("Missing Pragma: no-cache on {path}"),
                format!("Sensitive page {url} lacks Pragma: no-cache for HTTP/1.0 compatibility"),
                Evidence {
                    request: Some(req_rec.clone()),
                    response: Some(resp_rec.clone()),
                    detail: "Pragma header missing or does not contain no-cache".into(),
                },
                format!("Add Pragma: no-cache to {path} for HTTP/1.0 backward compatibility."),
            ));
        }

        if has_etag {
            findings.push(make_finding(
                "VC-INFRA-003",
                FindingSeverity::Low,
                format!("ETag on sensitive page {path}"),
                format!("Sensitive page {url} returns ETag header, can be used for user tracking"),
                Evidence {
                    request: Some(req_rec.clone()),
                    response: Some(resp_rec.clone()),
                    detail: "ETag header present on sensitive page".into(),
                },
                "Remove ETag header from sensitive pages or use Cache-Control: no-store.".into(),
            ));
        }
    }
    findings
}

pub async fn check_information_headers(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let resp = match safe_get(client, target, safety).await {
        Some(r) => r,
        None => return vec![],
    };

    let req_rec = request_record("GET", target, &[]);
    let resp_rec = capture_response(&resp, "GET", target);
    let mut findings = Vec::new();

    let info_headers: &[(&str, FindingSeverity, &str, &str)] = &[
        ("x-request-id", FindingSeverity::Low, "X-Request-Id header exposes internal infrastructure", "Remove X-Request-Id from responses sent to clients."),
        ("x-correlation-id", FindingSeverity::Low, "X-Correlation-Id header exposes internal infrastructure", "Remove X-Correlation-Id from responses sent to clients."),
        ("x-runtime", FindingSeverity::Low, "X-Runtime header leaks timing information", "Remove X-Runtime header from production responses."),
        ("x-debug-token", FindingSeverity::Medium, "X-Debug-Token header exposes debug tokens", "Disable debug mode in production and remove X-Debug-Token."),
        ("x-backend-server", FindingSeverity::Medium, "X-Backend-Server header leaks internal server names", "Remove X-Backend-Server from responses sent to clients."),
        ("x-amzn-trace-id", FindingSeverity::Low, "X-Amzn-Trace-Id header exposes AWS infrastructure", "Remove X-Amzn-Trace-Id from responses sent to clients."),
    ];

    for (header, severity, title, fix) in info_headers {
        let val = match resp.headers().get(*header).and_then(|v| v.to_str().ok()) {
            Some(v) => v.to_string(),
            None => continue,
        };
        findings.push(make_finding(
            "VC-INFRA-001",
            severity.clone(),
            title.to_string(),
            format!("{title} at {target}: {val}"),
            Evidence {
                request: Some(req_rec.clone()),
                response: Some(resp_rec.clone()),
                detail: format!("{header}: {val}"),
            },
            fix.to_string(),
        ));
    }

    if let Some(via_val) = resp.headers().get("via").and_then(|v| v.to_str().ok()) {
        let internal_re = regex::Regex::new(r"(?i)(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|[a-z]+-[a-z]+-\d+|internal|private)").unwrap();
        if internal_re.is_match(via_val) {
            findings.push(make_finding(
                "VC-INFRA-001",
                FindingSeverity::Low,
                "Via header reveals internal hostnames".into(),
                format!("Via header at {target} exposes proxy chain: {via_val}"),
                Evidence {
                    request: Some(req_rec.clone()),
                    response: Some(resp_rec.clone()),
                    detail: format!("Via: {via_val}"),
                },
                "Sanitize the Via header to remove internal hostnames and IP addresses.".into(),
            ));
        }
    }

    findings
}

fn minimal_urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

async fn find_existing_endpoint(client: &Client, base: &str, candidates: &[&str], safety: &Safety) -> Option<String> {
    for path in candidates {
        let url = format!("{base}{path}");
        let resp = match safe_get(client, &url, safety).await {
            Some(r) => r,
            None => continue,
        };
        if resp.status().as_u16() != 404 {
            return Some(url);
        }
    }
    None
}

pub async fn check_rate_limiting(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let mut endpoints: Vec<String> = Vec::new();

    if let Some(login_url) = find_existing_endpoint(
        client, base, &["/login", "/api/login", "/auth/login"], safety,
    ).await {
        endpoints.push(login_url);
    }

    let api_root = format!("{base}/api/");
    if let Some(resp) = safe_get(client, &api_root, safety).await {
        if resp.status().as_u16() != 404 {
            endpoints.push(api_root);
        }
    }

    endpoints.push(target.to_string());

    let mut findings = Vec::new();
    for endpoint in &endpoints {
        let mut got_429 = false;
        let mut has_retry_after = false;
        for _ in 0..10 {
            let resp = match safe_get(client, endpoint, safety).await {
                Some(r) => r,
                None => break,
            };
            if resp.status().as_u16() == 429 {
                got_429 = true;
                break;
            }
            if resp.headers().get("retry-after").is_some() {
                has_retry_after = true;
                break;
            }
        }
        if got_429 || has_retry_after {
            continue;
        }
        let path = endpoint.strip_prefix(base).unwrap_or(endpoint);
        let display_path = if path.is_empty() { "/" } else { path };
        findings.push(make_finding(
            "VC-BIZ-002",
            FindingSeverity::Medium,
            format!("No rate limiting detected on {display_path}"),
            format!("Sent 10 sequential requests to {endpoint} without receiving HTTP 429 or Retry-After header"),
            Evidence {
                request: Some(request_record("GET", endpoint, &[])),
                response: None,
                detail: format!("10 requests to {display_path} completed without rate limit response"),
            },
            "Implement rate limiting on authentication and sensitive endpoints (e.g., 5 req/min on login).".into(),
        ));
    }
    findings
}

pub async fn check_response_headers_advanced(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let base = target.trim_end_matches('/');
    let mut findings = Vec::new();

    let resp = match safe_get(client, target, safety).await {
        Some(r) => r,
        None => return vec![],
    };

    let header_names: Vec<String> = resp.headers().keys().map(|k| k.to_string().to_lowercase()).collect();
    let req_rec = request_record("GET", target, &[]);
    let resp_rec = capture_response(&resp, "GET", target);

    let cross_origin_headers: &[(&str, &str)] = &[
        ("x-xss-protection", "Missing X-XSS-Protection header"),
        ("cross-origin-opener-policy", "Missing Cross-Origin-Opener-Policy (COOP) header"),
        ("cross-origin-resource-policy", "Missing Cross-Origin-Resource-Policy (CORP) header"),
        ("cross-origin-embedder-policy", "Missing Cross-Origin-Embedder-Policy (COEP) header"),
    ];

    for (header, title) in cross_origin_headers {
        if header_names.iter().any(|h| h == *header) {
            continue;
        }
        findings.push(make_finding(
            "VC-INFRA-003",
            FindingSeverity::Low,
            title.to_string(),
            format!("Response from {target} is missing the {header} header"),
            Evidence {
                request: Some(req_rec.clone()),
                response: Some(resp_rec.clone()),
                detail: format!("{header} header not found in response"),
            },
            format!("Add the {header} header to responses"),
        ));
    }

    let sensitive_paths = ["/login", "/account", "/dashboard", "/profile"];
    let mut urls_to_check: Vec<String> = vec![target.to_string()];
    for path in &sensitive_paths {
        let url = format!("{base}{path}");
        if let Some(r) = safe_get(client, &url, safety).await {
            if r.status().as_u16() != 404 {
                urls_to_check.push(url);
            }
        }
    }

    for url in &urls_to_check {
        let resp = match safe_get(client, url, safety).await {
            Some(r) => r,
            None => continue,
        };
        let cache_control = resp.headers().get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        let resp_rec_cc = capture_response(&resp, "GET", url);
        let path = url.strip_prefix(base).unwrap_or(url);
        let is_sensitive = path == "/" || sensitive_paths.iter().any(|p| path.starts_with(p));
        if !is_sensitive {
            continue;
        }
        if cache_control.contains("no-store") {
            continue;
        }
        findings.push(make_finding(
            "VC-INFRA-003",
            FindingSeverity::Medium,
            format!("Missing Cache-Control: no-store on {path}"),
            format!("Sensitive page at {url} may be cached by the browser"),
            Evidence {
                request: Some(request_record("GET", url, &[])),
                response: Some(resp_rec_cc),
                detail: format!("Cache-Control header: '{cache_control}' (expected no-store)"),
            },
            "Add Cache-Control: no-store to responses for sensitive pages to prevent browser caching.".into(),
        ));
    }

    findings
}

pub async fn check_subdomain_hints(client: &Client, target: &str, safety: &Safety) -> Vec<Finding> {
    let parsed = match url::Url::parse(target) {
        Ok(u) => u,
        Err(_) => return vec![],
    };
    let host = match parsed.host_str() {
        Some(h) => h.to_string(),
        None => return vec![],
    };

    let resp = match safe_get(client, target, safety).await {
        Some(r) => r,
        None => return vec![],
    };
    let body = resp.text().await.unwrap_or_default();

    let prefixes = [
        "api", "admin", "staging", "dev", "test", "beta", "internal",
        "mail", "vpn", "git", "ci", "jenkins", "grafana",
    ];

    let mut found_subdomains: Vec<String> = Vec::new();
    for prefix in &prefixes {
        let subdomain = format!("{prefix}.{host}");
        if body.contains(&subdomain) && !found_subdomains.contains(&subdomain) {
            found_subdomains.push(subdomain);
        }
    }

    let mut findings = Vec::new();
    for subdomain in &found_subdomains {
        findings.push(make_finding(
            "VC-INFRA-001",
            FindingSeverity::Low,
            format!("Subdomain reference found: {subdomain}"),
            format!("HTML body of {target} references {subdomain}"),
            Evidence {
                request: Some(request_record("GET", target, &[])),
                response: None,
                detail: format!("Found reference to {subdomain} in page body"),
            },
            "Review whether subdomain references in HTML expose internal infrastructure.".into(),
        ));
    }
    findings
}
