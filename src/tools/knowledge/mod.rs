mod best_practices;
mod check_pattern;
mod checklist;
mod explain;
mod owasp;

pub use best_practices::best_practice;
pub use check_pattern::check_pattern;
pub use checklist::security_checklist;
pub use explain::explain_vuln;
pub use owasp::owasp_check;

use crate::mcp::protocol::{Content, ToolCallResult};

pub(super) fn text_result(text: &str) -> ToolCallResult {
    ToolCallResult {
        content: vec![Content::Text {
            text: text.to_string(),
        }],
        is_error: None,
    }
}

pub(super) fn error_result(text: &str) -> ToolCallResult {
    ToolCallResult {
        content: vec![Content::Text {
            text: text.to_string(),
        }],
        is_error: Some(true),
    }
}
