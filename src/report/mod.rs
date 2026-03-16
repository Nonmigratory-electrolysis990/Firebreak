use crate::types::*;

pub fn generate_json(summary: &ScanSummary, findings: &[Finding]) -> String {
    let report = serde_json::json!({
        "summary": {
            "scan_id": summary.scan_id,
            "target_url": summary.target_url,
            "grade": summary.grade.to_string(),
            "findings": {
                "critical": summary.critical,
                "high": summary.high,
                "medium": summary.medium,
                "low": summary.low,
                "total": summary.total,
            },
            "top_risks": summary.top_risks,
        },
        "findings": findings,
    });
    serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

pub fn generate_markdown(summary: &ScanSummary, findings: &[Finding]) -> String {
    let now = chrono::Utc::now().to_rfc3339();

    let mut md = format!(
        "# Firebreak Security Report\n\
         ## Target: {target}\n\
         ## Score: {grade}\n\
         ## Date: {now}\n\n\
         ### Summary\n\n\
         | Severity | Count |\n\
         |----------|-------|\n\
         | Critical | {critical} |\n\
         | High     | {high} |\n\
         | Medium   | {medium} |\n\
         | Low      | {low} |\n\
         | **Total** | **{total}** |\n\n\
         ### Findings\n\n",
        target = summary.target_url,
        grade = summary.grade,
        critical = summary.critical,
        high = summary.high,
        medium = summary.medium,
        low = summary.low,
        total = summary.total,
    );

    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| a.severity.cmp(&b.severity));

    let mut current_severity: Option<&FindingSeverity> = None;
    for f in &sorted {
        if current_severity.map(|s| s != &f.severity).unwrap_or(true) {
            current_severity = Some(&f.severity);
        }
        md.push_str(&format!(
            "#### {} {}: {}\n\
             **VCVD**: {}\n\
             **Evidence**: {}\n\
             **Fix**: {}\n\n\
             ---\n\n",
            f.severity.emoji(),
            f.severity,
            f.title,
            f.vcvd_id,
            f.evidence.detail,
            f.fix_suggestion,
        ));
    }

    md
}

pub fn generate_html(summary: &ScanSummary, findings: &[Finding]) -> String {
    let now = chrono::Utc::now().to_rfc3339();

    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| a.severity.cmp(&b.severity));

    let mut findings_html = String::new();
    for f in &sorted {
        let sev_class = match f.severity {
            FindingSeverity::Critical => "critical",
            FindingSeverity::High => "high",
            FindingSeverity::Medium => "medium",
            FindingSeverity::Low => "low",
        };
        findings_html.push_str(&format!(
            "<div class=\"finding {sev_class}\">\
             <h3>{emoji} {severity}: {title}</h3>\
             <p><strong>VCVD</strong>: {vcvd}</p>\
             <p><strong>Evidence</strong>: {evidence}</p>\
             <p><strong>Fix</strong>: {fix}</p>\
             </div>\n",
            emoji = html_escape(f.severity.emoji()),
            severity = f.severity,
            title = html_escape(&f.title),
            vcvd = html_escape(&f.vcvd_id),
            evidence = html_escape(&f.evidence.detail),
            fix = html_escape(&f.fix_suggestion),
        ));
    }

    format!(
        "<!DOCTYPE html>\n\
         <html lang=\"en\">\n\
         <head>\n\
         <meta charset=\"UTF-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n\
         <title>Firebreak Security Report — {target}</title>\n\
         <style>\n\
         body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; \
         max-width: 900px; margin: 0 auto; padding: 2rem; background: #0d1117; color: #c9d1d9; }}\n\
         h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }}\n\
         h2 {{ color: #8b949e; }}\n\
         table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}\n\
         th, td {{ border: 1px solid #30363d; padding: 0.5rem 1rem; text-align: left; }}\n\
         th {{ background: #161b22; color: #58a6ff; }}\n\
         .finding {{ border: 1px solid #30363d; border-radius: 6px; padding: 1rem; margin: 1rem 0; }}\n\
         .critical {{ border-left: 4px solid #f85149; }}\n\
         .high {{ border-left: 4px solid #d29922; }}\n\
         .medium {{ border-left: 4px solid #58a6ff; }}\n\
         .low {{ border-left: 4px solid #8b949e; }}\n\
         .grade {{ font-size: 3rem; font-weight: bold; }}\n\
         .grade-a {{ color: #3fb950; }} .grade-b {{ color: #58a6ff; }} .grade-c {{ color: #d29922; }}\n\
         .grade-d {{ color: #f85149; }} .grade-f {{ color: #f85149; }}\n\
         </style>\n\
         </head>\n\
         <body>\n\
         <h1>Firebreak Security Report</h1>\n\
         <p><strong>Target</strong>: {target}</p>\n\
         <p><strong>Date</strong>: {now}</p>\n\
         <p class=\"grade grade-{grade_lower}\">Grade: {grade}</p>\n\
         <h2>Summary</h2>\n\
         <table>\n\
         <tr><th>Severity</th><th>Count</th></tr>\n\
         <tr><td>Critical</td><td>{critical}</td></tr>\n\
         <tr><td>High</td><td>{high}</td></tr>\n\
         <tr><td>Medium</td><td>{medium}</td></tr>\n\
         <tr><td>Low</td><td>{low}</td></tr>\n\
         <tr><th>Total</th><th>{total}</th></tr>\n\
         </table>\n\
         <h2>Findings</h2>\n\
         {findings_html}\
         </body>\n\
         </html>",
        target = html_escape(&summary.target_url),
        grade = summary.grade,
        grade_lower = summary.grade.to_lowercase().next().unwrap_or('a'),
        critical = summary.critical,
        high = summary.high,
        medium = summary.medium,
        low = summary.low,
        total = summary.total,
    )
}

pub fn executive_summary(summary: &ScanSummary, findings: &[Finding]) -> String {
    let risk_level = match summary.grade {
        'A' => "Low Risk",
        'B' => "Moderate Risk",
        'C' => "Elevated Risk",
        'D' => "High Risk",
        _ => "Critical Risk",
    };

    let risk_explanation = match summary.grade {
        'A' => "The application demonstrates strong security posture with only minor issues detected.",
        'B' => "The application has some security concerns that should be addressed in the near term.",
        'C' => "The application has notable security weaknesses that require prompt attention.",
        'D' => "The application has serious security vulnerabilities that need immediate remediation.",
        _ => "The application has critical security failures that pose immediate risk to the business and its users.",
    };

    let mut actions = Vec::new();
    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| a.severity.cmp(&b.severity));

    for f in sorted.iter().take(3) {
        let urgency = match f.severity {
            FindingSeverity::Critical => "IMMEDIATELY",
            FindingSeverity::High => "within 24 hours",
            FindingSeverity::Medium => "within 1 week",
            FindingSeverity::Low => "during next sprint",
        };
        actions.push(format!("Fix **{}** ({}) — {}", f.title, f.vcvd_id, urgency));
    }

    if actions.is_empty() {
        actions.push("No vulnerabilities found — maintain current security practices.".into());
    }

    let mut md = format!(
        "# Executive Security Summary\n\n\
         **Target**: {target}\n\
         **Assessment Date**: {date}\n\n\
         ## Risk Level: {risk_level}\n\
         **Security Grade: {grade}**\n\n\
         {risk_explanation}\n\n\
         ## Key Metrics\n\n\
         - **{total}** total vulnerabilities found\n\
         - **{critical}** critical (immediate business impact)\n\
         - **{high}** high severity\n\
         - **{medium}** medium severity\n\
         - **{low}** low severity\n\n\
         ## Top 3 Priority Actions\n\n",
        target = summary.target_url,
        date = chrono::Utc::now().format("%Y-%m-%d"),
        grade = summary.grade,
        total = summary.total,
        critical = summary.critical,
        high = summary.high,
        medium = summary.medium,
        low = summary.low,
    );

    for (i, action) in actions.iter().enumerate() {
        md.push_str(&format!("{}. {}\n", i + 1, action));
    }

    md.push_str("\n## Business Impact\n\n");
    if summary.critical > 0 {
        md.push_str(
            "Critical vulnerabilities were found that could lead to data breaches, \
             unauthorized access, or service disruption. These issues may have regulatory \
             implications (GDPR, SOC2, PCI-DSS) and should be treated as P0 incidents.\n",
        );
    } else if summary.high > 0 {
        md.push_str(
            "High severity issues were found that could be exploited by motivated attackers. \
             While not immediately critical, these should be prioritized in the next development cycle.\n",
        );
    } else {
        md.push_str(
            "No critical or high severity issues were found. The application maintains \
             a reasonable security baseline. Continue regular security assessments.\n",
        );
    }

    md
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
