use crate::mcp::protocol::ToolCallResult;
use crate::vcvd::{lookup, PATTERNS};

static ALIASES: &[(&str, &str)] = &[
    ("IDOR", "VC-DATA-001"),
    ("XSS", "VC-INJ-002"),
    ("CSRF", "VC-FE-004"),
    ("SSRF", "VC-INJ-006"),
    ("SQLi", "VC-INJ-001"),
    ("RCE", "VC-INJ-004"),
];

fn resolve_id(id: &str) -> &str {
    let upper = id.to_uppercase();
    ALIASES
        .iter()
        .find(|(alias, _)| alias.to_uppercase() == upper)
        .map(|(_, vcvd_id)| *vcvd_id)
        .unwrap_or(id)
}

pub fn explain_vuln(id: &str) -> ToolCallResult {
    let resolved = resolve_id(id.trim());

    if let Some(pattern) = lookup(resolved) {
        let output = format!(
            "# {} ({})\n\
             Severity: {}\n\
             Category: {}\n\
             OWASP: {}\n\
             CWE: CWE-{}\n\
             \n\
             ## What is it?\n\
             {}\n\
             \n\
             ## How AI generates this\n\
             {}\n\
             \n\
             ## How to detect\n\
             {}\n\
             \n\
             ## How to fix\n\
             {}",
            pattern.name,
            pattern.id,
            pattern.severity,
            pattern.category,
            pattern.owasp,
            pattern.cwe,
            pattern.description,
            pattern.ai_pattern,
            pattern.detection_hint,
            pattern.fix,
        );
        return super::text_result(&output);
    }

    let available: Vec<&str> = PATTERNS.iter().map(|p| p.id).collect();
    super::error_result(&format!(
        "Unknown vulnerability '{}'. Available VCVD IDs: {}",
        id,
        available.join(", ")
    ))
}
