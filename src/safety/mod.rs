use crate::types::AuditEntry;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use url::Url;

pub struct Safety {
    max_rps: u32,
    target_scope: Mutex<Option<String>>,
    request_times: Mutex<Vec<Instant>>,
    audit_log: Mutex<Vec<AuditEntry>>,
    consent_given: Mutex<bool>,
}

impl Safety {
    pub fn new(max_rps: u32) -> Self {
        Self {
            max_rps,
            target_scope: Mutex::new(None),
            request_times: Mutex::new(Vec::new()),
            audit_log: Mutex::new(Vec::new()),
            consent_given: Mutex::new(false),
        }
    }

    pub fn set_scope(&self, target: &str) {
        let host = Url::parse(target)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()));
        *self.target_scope.lock().unwrap() = host;
    }

    pub fn check_scope(&self, url: &str) -> bool {
        let scope = self.target_scope.lock().unwrap();
        let scope_host = match scope.as_deref() {
            Some(h) => h,
            None => return false,
        };
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return false,
        };
        let request_host = match parsed.host_str() {
            Some(h) => h,
            None => return false,
        };
        request_host == scope_host || request_host.ends_with(&format!(".{}", scope_host))
    }

    pub async fn acquire_rate_limit(&self) -> bool {
        let mut times = self.request_times.lock().unwrap();
        let cutoff = Instant::now() - Duration::from_secs(1);
        times.retain(|t| *t > cutoff);
        if (times.len() as u32) < self.max_rps {
            times.push(Instant::now());
            return true;
        }
        false
    }

    pub fn log_action(&self, action: &str, target: &str, detail: &str) {
        self.audit_log.lock().unwrap().push(AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            action: action.to_string(),
            target: target.to_string(),
            detail: detail.to_string(),
        });
    }

    pub fn set_consent(&self, consent: bool) {
        *self.consent_given.lock().unwrap() = consent;
    }

    pub fn has_consent(&self) -> bool {
        *self.consent_given.lock().unwrap()
    }

    pub fn get_audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.lock().unwrap().clone()
    }
}
