use crate::types::*;
use rusqlite::{Connection, OptionalExtension, params};
use std::sync::Mutex;

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn new(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        let store = Self { conn: Mutex::new(conn) };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                mode TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                progress INTEGER NOT NULL DEFAULT 0,
                phase TEXT NOT NULL DEFAULT 'initializing',
                findings_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                vcvd_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence_json TEXT NOT NULL DEFAULT '{}',
                fix_suggestion TEXT NOT NULL DEFAULT '',
                verified INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                detail TEXT NOT NULL
            );"
        ).map_err(|e| e.to_string())
    }

    pub fn create_scan(&self, scan: &Scan) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let mode = serde_json::to_value(&scan.mode).map_err(|e| e.to_string())?;
        let status = serde_json::to_value(&scan.status).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO scans (id, target_url, mode, status, progress, phase, findings_count, created_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                scan.id,
                scan.target_url,
                mode.as_str().unwrap(),
                status.as_str().unwrap(),
                scan.progress,
                scan.phase,
                scan.findings_count as i64,
                scan.created_at,
                scan.completed_at,
            ],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_scan(&self, id: &str) -> Result<Option<Scan>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, target_url, mode, status, progress, phase, findings_count, created_at, completed_at FROM scans WHERE id = ?1",
            params![id],
            |row| Ok(row_to_scan(row)),
        ).optional().map_err(|e| e.to_string())?
            .map(|r| r.map_err(|e| e.to_string()))
            .transpose()
    }

    pub fn update_scan_status(&self, id: &str, status: &ScanStatus, progress: u8, phase: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let status_str = serde_json::to_value(status).map_err(|e| e.to_string())?;
        conn.execute(
            "UPDATE scans SET status = ?1, progress = ?2, phase = ?3 WHERE id = ?4",
            params![status_str.as_str().unwrap(), progress, phase, id],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn complete_scan(&self, id: &str, findings_count: usize) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE scans SET status = 'completed', completed_at = ?1, findings_count = ?2 WHERE id = ?3",
            params![now, findings_count as i64, id],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_scans(&self, target_url: Option<&str>, limit: usize) -> Result<Vec<Scan>, String> {
        let conn = self.conn.lock().unwrap();
        let mut scans = Vec::new();
        match target_url {
            Some(url) => {
                let mut stmt = conn.prepare(
                    "SELECT id, target_url, mode, status, progress, phase, findings_count, created_at, completed_at
                     FROM scans WHERE target_url = ?1 ORDER BY created_at DESC LIMIT ?2"
                ).map_err(|e| e.to_string())?;
                let rows = stmt.query_map(params![url, limit as i64], |row| Ok(row_to_scan(row)))
                    .map_err(|e| e.to_string())?;
                for row in rows {
                    scans.push(row.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?);
                }
            }
            None => {
                let mut stmt = conn.prepare(
                    "SELECT id, target_url, mode, status, progress, phase, findings_count, created_at, completed_at
                     FROM scans ORDER BY created_at DESC LIMIT ?1"
                ).map_err(|e| e.to_string())?;
                let rows = stmt.query_map(params![limit as i64], |row| Ok(row_to_scan(row)))
                    .map_err(|e| e.to_string())?;
                for row in rows {
                    scans.push(row.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?);
                }
            }
        }
        Ok(scans)
    }

    pub fn add_finding(&self, finding: &Finding) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let severity = serde_json::to_value(&finding.severity).map_err(|e| e.to_string())?;
        let evidence_json = serde_json::to_string(&finding.evidence).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO findings (id, scan_id, vcvd_id, severity, title, description, evidence_json, fix_suggestion, verified)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                finding.id,
                finding.scan_id,
                finding.vcvd_id,
                severity.as_str().unwrap(),
                finding.title,
                finding.description,
                evidence_json,
                finding.fix_suggestion,
                finding.verified as i32,
            ],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_finding(&self, id: &str) -> Result<Option<Finding>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, scan_id, vcvd_id, severity, title, description, evidence_json, fix_suggestion, verified
             FROM findings WHERE id = ?1",
            params![id],
            |row| Ok(row_to_finding(row)),
        ).optional().map_err(|e| e.to_string())?
            .map(|r| r.map_err(|e| e.to_string()))
            .transpose()
    }

    pub fn get_findings_by_scan(&self, scan_id: &str) -> Result<Vec<Finding>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, scan_id, vcvd_id, severity, title, description, evidence_json, fix_suggestion, verified
             FROM findings WHERE scan_id = ?1"
        ).map_err(|e| e.to_string())?;
        let rows = stmt.query_map(params![scan_id], |row| Ok(row_to_finding(row)))
            .map_err(|e| e.to_string())?;
        let mut findings = Vec::new();
        for row in rows {
            findings.push(row.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?);
        }
        Ok(findings)
    }

    pub fn add_audit_entry(&self, entry: &AuditEntry) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, target, detail) VALUES (?1, ?2, ?3, ?4)",
            params![entry.timestamp, entry.action, entry.target, entry.detail],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn row_to_scan(row: &rusqlite::Row) -> Result<Scan, String> {
    let mode_str: String = row.get(2).map_err(|e| e.to_string())?;
    let status_str: String = row.get(3).map_err(|e| e.to_string())?;
    let findings_count: i64 = row.get(6).map_err(|e| e.to_string())?;
    let mode: ScanMode = serde_json::from_str(&format!("\"{}\"", mode_str)).map_err(|e| e.to_string())?;
    let status: ScanStatus = serde_json::from_str(&format!("\"{}\"", status_str)).map_err(|e| e.to_string())?;
    Ok(Scan {
        id: row.get(0).map_err(|e| e.to_string())?,
        target_url: row.get(1).map_err(|e| e.to_string())?,
        mode,
        status,
        progress: row.get::<_, u8>(4).map_err(|e| e.to_string())?,
        phase: row.get(5).map_err(|e| e.to_string())?,
        findings_count: findings_count as usize,
        created_at: row.get(7).map_err(|e| e.to_string())?,
        completed_at: row.get(8).map_err(|e| e.to_string())?,
    })
}

fn row_to_finding(row: &rusqlite::Row) -> Result<Finding, String> {
    let severity_str: String = row.get(3).map_err(|e| e.to_string())?;
    let evidence_json: String = row.get(6).map_err(|e| e.to_string())?;
    let verified_int: i32 = row.get(8).map_err(|e| e.to_string())?;
    let severity: FindingSeverity = serde_json::from_str(&format!("\"{}\"", severity_str)).map_err(|e| e.to_string())?;
    let evidence: Evidence = serde_json::from_str(&evidence_json).map_err(|e| e.to_string())?;
    Ok(Finding {
        id: row.get(0).map_err(|e| e.to_string())?,
        scan_id: row.get(1).map_err(|e| e.to_string())?,
        vcvd_id: row.get(2).map_err(|e| e.to_string())?,
        severity,
        title: row.get(4).map_err(|e| e.to_string())?,
        description: row.get(5).map_err(|e| e.to_string())?,
        evidence,
        fix_suggestion: row.get(7).map_err(|e| e.to_string())?,
        verified: verified_int != 0,
    })
}
