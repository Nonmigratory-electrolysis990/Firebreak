use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: String,
    pub target_url: String,
    pub mode: ScanMode,
    pub status: ScanStatus,
    pub progress: u8,
    pub phase: String,
    pub findings_count: usize,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Black,
    Gray,
    White,
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Black => write!(f, "black"),
            Self::Gray => write!(f, "gray"),
            Self::White => write!(f, "white"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Running,
    Completed,
    Stopped,
    Failed,
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Stopped => write!(f, "stopped"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub max_rps: u32,
    pub timeout_secs: u64,
    pub skip_rules: Vec<String>,
    pub focus: Option<String>,
    pub credentials: Vec<Credential>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_rps: 10,
            timeout_secs: 300,
            skip_rules: vec![],
            focus: None,
            credentials: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub scan_id: String,
    pub vcvd_id: String,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub evidence: Evidence,
    pub fix_suggestion: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
        }
    }
}

impl FindingSeverity {
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Critical => "🔴",
            Self::High => "🟡",
            Self::Medium => "🔵",
            Self::Low => "⚪",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Evidence {
    pub request: Option<HttpRecord>,
    pub response: Option<HttpRecord>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRecord {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub target_url: String,
    pub grade: char,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total: usize,
    pub top_risks: Vec<String>,
}

impl ScanSummary {
    pub fn calculate_grade(critical: usize, high: usize, medium: usize) -> char {
        if critical >= 3 {
            return 'F';
        }
        if critical >= 1 || high > 5 {
            return 'D';
        }
        if high > 2 || (high > 0 && medium > 5) {
            return 'C';
        }
        if high > 0 || medium > 2 {
            return 'B';
        }
        'A'
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub steps: Vec<AttackStep>,
    pub total_impact: String,
    pub business_risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub order: usize,
    pub finding_id: String,
    pub description: String,
}
