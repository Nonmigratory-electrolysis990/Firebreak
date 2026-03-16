mod data;

pub use data::PATTERNS;

#[derive(Debug, Clone)]
pub struct VcvdPattern {
    pub id: &'static str,
    pub name: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub description: &'static str,
    pub ai_pattern: &'static str,
    pub detection_hint: &'static str,
    pub fix: &'static str,
    pub owasp: &'static str,
    pub cwe: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Category {
    Auth,
    Data,
    Injection,
    Infra,
    Frontend,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth => write!(f, "Auth & Identity"),
            Self::Data => write!(f, "Data Access"),
            Self::Injection => write!(f, "Injection"),
            Self::Infra => write!(f, "Infrastructure"),
            Self::Frontend => write!(f, "Frontend"),
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
        }
    }
}

pub fn lookup(id: &str) -> Option<&'static VcvdPattern> {
    let normalized = id.to_uppercase();
    PATTERNS.iter().find(|p| p.id == normalized)
}

#[allow(dead_code)]
pub fn by_category(cat: Category) -> Vec<&'static VcvdPattern> {
    PATTERNS.iter().filter(|p| p.category == cat).collect()
}
